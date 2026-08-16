from typing import TypedDict, List, Optional
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


def build_graph(mcp_client: SplunkMCPClient, agent_memory: AgentMemory, game_tree: GameTree, classifier: TacticClassifier, llm_client: LLMClient):
    
    async def ingest_signal(state: AgentState) -> AgentState:
        if not state.get("episode_id"):
            state["episode_id"] = str(uuid4())
        return state

    async def pull_splunk_context(state: AgentState) -> AgentState:
        signal = state["signal"]
        errors = state.get("errors", [])
        
        query = host_activity_summary(signal.host, 60)
        
        # We will still pull the basic search, but also pull the full context
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
            
        state["splunk_context"] = context
        state["errors"] = errors
        return state

    async def classify_tactic(state: AgentState) -> AgentState:
        signal = state["signal"]
        tactic, tactic_id, conf = await classifier.classify(signal)
        state["tactic_classification"] = tactic
        state["tactic_id"] = tactic_id
        state["tactic_confidence"] = conf
        return state

    async def expand_game_tree(state: AgentState) -> AgentState:
        signal = state["signal"]
        tactic = state["tactic_classification"]
        context = state["splunk_context"]
        moves = await game_tree.expand(signal, tactic, context)
        state["scored_moves"] = moves
        return state

    async def score_and_prune(state: AgentState) -> AgentState:
        moves = state.get("scored_moves")
        if not moves:
            state["scored_moves"] = []
            return state
            
        signal = state.get("signal")
        context = state.get("splunk_context")
        
        print(f"[score_and_prune] Re-scoring {len(moves)} moves with LLM provider: {llm_client.provider}")
        
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
        return state

    async def generate_brief(state: AgentState) -> AgentState:
        signal = state["signal"]
        context = state["splunk_context"]
        moves = state.get("scored_moves") or []
        
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

async def run_agent(signal: ObservedSignal, mcp_client: SplunkMCPClient, agent_memory: AgentMemory, game_tree: GameTree, classifier: TacticClassifier, llm_client: LLMClient) -> DefenderBrief:
    graph = build_graph(mcp_client, agent_memory, game_tree, classifier, llm_client)
    
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
