from typing import TypedDict, List, Optional, Callable, Any
from uuid import uuid4
from langgraph.graph import StateGraph, START, END
from agent.schemas import ObservedSignal, SplunkContext, PredictedMove, DefenderBrief, IncidentEpisode
from agent.memory import AgentMemory
from agent.classifier import TacticClassifier
from agent.game_tree import GameTree
from agent.llm_client import LLMClient
from splunk.mcp_client import SplunkMCPClient
from splunk.spl_templates import host_activity_summary
from datetime import datetime, timezone
import os
import inspect

class AgentState(TypedDict):
    signal: ObservedSignal
    splunk_context: Optional[SplunkContext]
    tactic_classification: Optional[str]
    tactic_id: Optional[str]
    tactic_confidence: Optional[float]
    scored_moves: Optional[List[PredictedMove]]
    defender_brief: Optional[DefenderBrief]
    episode_id: Optional[str]
    errors: List[str]


def build_graph(
    mcp_client: SplunkMCPClient,
    agent_memory: AgentMemory,
    game_tree: GameTree,
    classifier: TacticClassifier,
    llm_client: LLMClient,
    progress_callback: Optional[Callable[[int, str, str], Any]] = None
):
    async def notify(step: int, step_name: str, log_msg: str):
        if progress_callback:
            try:
                res = progress_callback(step, step_name, log_msg)
                if inspect.isawaitable(res):
                    await res
            except Exception as e:
                pass
    
    async def ingest_signal(state: AgentState) -> AgentState:
        signal = state["signal"]
        if not state.get("episode_id"):
            state["episode_id"] = str(uuid4())
        await notify(1, "Ingest Signal", f"Received attack signal from host {signal.host}: {signal.event_type} ({signal.severity} severity)")
        return state

    async def pull_splunk_context(state: AgentState) -> AgentState:
        signal = state["signal"]
        errors = state.get("errors", [])
        
        await notify(2, "Pull Splunk Context", f"Querying Splunk MCP Server for {signal.host} process & auth telemetry (60m window)...")
        query = host_activity_summary(signal.host, 60)
        
        result = await mcp_client.search(query)
        context_data = await mcp_client.pull_host_context(signal.host, 60)
        
        proc_evts = context_data.get("process_events").data if context_data.get("process_events") and context_data["process_events"].success else []
        auth_evts = context_data.get("auth_events").data if context_data.get("auth_events") and context_data["auth_events"].success else []
        net_evts = context_data.get("network_events").data if context_data.get("network_events") and context_data["network_events"].success else []
        host_sum = context_data.get("host_summary").data if context_data.get("host_summary") and context_data["host_summary"].success else []
        
        is_bad_data = False
        if result.success and isinstance(result.data, list) and len(result.data) > 0:
            first_item = result.data[0]
            if isinstance(first_item, dict) and ("error" in first_item or "messages" in first_item):
                is_bad_data = True

        if not result.success or is_bad_data:
            err_msg = result.error if not result.success else str(result.data[0])
            errors.append(f"Splunk MCP Error: {err_msg}")
            
            context = SplunkContext(
                host=signal.host,
                query_window_minutes=60,
                process_events=[],
                auth_events=[],
                network_events=[],
                host_summary=[],
                raw_results={}
            )
            await notify(2, "Pull Splunk Context", f"Splunk MCP lookup fallback used. Context initialized for {signal.host}.")
        else:
            context = SplunkContext(
                host=signal.host,
                query_window_minutes=60,
                process_events=proc_evts if isinstance(proc_evts, list) else [],
                auth_events=auth_evts if isinstance(auth_evts, list) else [],
                network_events=net_evts if isinstance(net_evts, list) else [],
                host_summary=host_sum if isinstance(host_sum, list) else [],
                raw_results={"data": result.data}
            )
            await notify(2, "Pull Splunk Context", f"Retrieved Splunk context ({context.total_events} events) for {signal.host}.")
            
        state["splunk_context"] = context
        state["errors"] = errors
        return state

    async def classify_tactic(state: AgentState) -> AgentState:
        signal = state["signal"]
        await notify(3, "Classify Tactic", f"Analyzing event payload against MITRE ATT&CK tactic taxonomy...")
        tactic, tactic_id, conf = await classifier.classify(signal)
        state["tactic_classification"] = tactic
        state["tactic_id"] = tactic_id
        state["tactic_confidence"] = conf
        await notify(3, "Classify Tactic", f"Tactic classified: {tactic} [{tactic_id}] (Confidence: {conf:.2f})")
        return state

    async def expand_game_tree(state: AgentState) -> AgentState:
        signal = state["signal"]
        tactic = state["tactic_classification"]
        context = state["splunk_context"]
        await notify(4, "Expand Game Tree", f"Searching MITRE ATT&CK semantic database (697 techniques) for candidate next moves under '{tactic}'...")
        moves = await game_tree.expand(signal, tactic, context)
        state["scored_moves"] = moves
        await notify(4, "Expand Game Tree", f"Identified {len(moves)} candidate next-move techniques.")
        return state

    async def score_and_prune(state: AgentState) -> AgentState:
        moves = state.get("scored_moves")
        if not moves:
            state["scored_moves"] = []
            await notify(5, "LLM Re-Score", "No candidate moves found to score.")
            return state
            
        signal = state.get("signal")
        context = state.get("splunk_context")
        
        await notify(5, "LLM Re-Score", f"Re-scoring {len(moves)} moves with LLM engine ({llm_client.provider})...")
        
        scored = await llm_client.score_moves(signal, context, moves)
        
        # Re-normalize probabilities
        total_prob = sum(m.probability for m in scored)
        if total_prob > 0:
            for m in scored:
                m.probability = m.probability / total_prob
        
        # Re-calculate confidence tier
        for m in scored:
            if m.probability >= 0.60:
                m.confidence_tier = "high"
            elif m.probability >= 0.30:
                m.confidence_tier = "medium"
            else:
                m.confidence_tier = "low"
                
        # Re-prune based on new threshold
        prune_threshold = float(os.getenv("PROBABILITY_PRUNE_THRESHOLD", "0.15"))
        pruned = [m for m in scored if m.probability >= prune_threshold]
        
        # Re-sort
        pruned.sort(key=lambda x: x.probability, reverse=True)
        
        # Cap at MAX_PREDICTIONS
        max_preds = int(os.getenv("MAX_PREDICTIONS", "5"))
        pruned = pruned[:max_preds]
        
        state["scored_moves"] = pruned
        top_name = pruned[0].technique_name if pruned else "None"
        top_prob = int(pruned[0].probability * 100) if pruned else 0
        await notify(5, "LLM Re-Score", f"Scored & normalized moves. Top prediction: {top_name} ({top_prob}%).")
        return state

    async def generate_brief(state: AgentState) -> AgentState:
        signal = state["signal"]
        context = state["splunk_context"]
        moves = state.get("scored_moves") or []
        
        await notify(6, "Generate Brief", "Building Defender Brief and persisting incident episode in memory...")
        top_prediction = moves[0] if moves else None
        
        episode_id_obj = uuid4()
        state["episode_id"] = str(episode_id_obj)
        
        brief = DefenderBrief(
            brief_id=episode_id_obj,
            signal_summary=f"{signal.severity.upper()} severity event on {signal.host}: {signal.event_type}",
            tactic_classification=state["tactic_classification"] or "Unknown",
            tactic_id=state["tactic_id"] or "TA0000",
            ranked_predictions=moves,
            top_prediction=top_prediction,
            context_summary=f"Found {context.total_events} events for {context.host}" if context else "No context available",
            splunk_context=context,
            generated_at=datetime.now(timezone.utc)
        )
        state["defender_brief"] = brief
        
        episode = IncidentEpisode(
            episode_id=episode_id_obj,
            signal=signal,
            predictions=moves,
            created_at=datetime.now(timezone.utc)
        )
        await agent_memory.store_episode(episode)
        await notify(6, "Generate Brief", f"Brief completed! Episode {str(episode_id_obj)[:8]} stored in ChromaDB.")
        
        return state

    builder = StateGraph(AgentState)
    builder.add_node("ingest_signal", ingest_signal)
    builder.add_node("pull_splunk_context", pull_splunk_context)
    builder.add_node("classify_tactic", classify_tactic)
    builder.add_node("expand_game_tree", expand_game_tree)
    builder.add_node("score_and_prune", score_and_prune)
    builder.add_node("generate_brief", generate_brief)
    
    builder.add_edge(START, "ingest_signal")
    builder.add_edge("ingest_signal", "pull_splunk_context")
    builder.add_edge("pull_splunk_context", "classify_tactic")
    builder.add_edge("classify_tactic", "expand_game_tree")
    builder.add_edge("expand_game_tree", "score_and_prune")
    builder.add_edge("score_and_prune", "generate_brief")
    builder.add_edge("generate_brief", END)
    
    return builder.compile()

async def run_agent(
    signal: ObservedSignal,
    mcp_client: SplunkMCPClient,
    agent_memory: AgentMemory,
    game_tree: GameTree,
    classifier: TacticClassifier,
    llm_client: LLMClient,
    progress_callback: Optional[Callable[[int, str, str], Any]] = None
) -> DefenderBrief:
    graph = build_graph(mcp_client, agent_memory, game_tree, classifier, llm_client, progress_callback)
    
    initial_state = {
        "signal": signal,
        "splunk_context": None,
        "tactic_classification": None,
        "tactic_id": None,
        "tactic_confidence": None,
        "scored_moves": None,
        "defender_brief": None,
        "episode_id": None,
        "errors": []
    }
    
    final_state = await graph.ainvoke(initial_state)
    return final_state["defender_brief"]
