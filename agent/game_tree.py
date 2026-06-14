import os
from typing import List
from agent.schemas import ObservedSignal, SplunkContext, PredictedMove
from agent.memory import AgentMemory
from memory.vector_store import VectorStore
from memory.semantic import search_techniques, embed_text

KILL_CHAIN_NEXT = {
    "Initial Access":        ["Execution", "Persistence", "Defense Evasion"],
    "Execution":             ["Persistence", "Privilege Escalation", "Defense Evasion"],
    "Persistence":           ["Privilege Escalation", "Defense Evasion", "Discovery"],
    "Privilege Escalation":  ["Defense Evasion", "Credential Access", "Discovery"],
    "Defense Evasion":       ["Credential Access", "Discovery", "Lateral Movement"],
    "Credential Access":     ["Lateral Movement", "Discovery", "Collection"],
    "Discovery":             ["Lateral Movement", "Collection", "Command and Control"],
    "Lateral Movement":      ["Collection", "Command and Control", "Exfiltration"],
    "Collection":            ["Command and Control", "Exfiltration"],
    "Command and Control":   ["Exfiltration", "Impact"],
    "Exfiltration":          ["Impact"],
    "Impact":                [],
    "Reconnaissance":        ["Initial Access", "Resource Development"],
    "Resource Development":  ["Initial Access"],
    "Unknown":               ["Execution", "Persistence", "Discovery"],
}

class GameTree:
    def __init__(self, agent_memory: AgentMemory, vector_store: VectorStore):
        self.agent_memory = agent_memory
        self.vector_store = vector_store
        
        self.depth = int(os.getenv("GAME_TREE_DEPTH", "1"))
        self.prune_threshold = float(os.getenv("PROBABILITY_PRUNE_THRESHOLD", "0.15"))
        self.max_predictions = int(os.getenv("MAX_PREDICTIONS", "5"))

    async def expand(self, signal: ObservedSignal, tactic: str, splunk_context: SplunkContext) -> List[PredictedMove]:
        next_tactics = KILL_CHAIN_NEXT.get(tactic, ["Execution", "Persistence", "Discovery"])
        
        candidates = []
        seen_ids = set()
        
        for next_tactic in next_tactics:
            techs = search_techniques(signal.raw_event, self.vector_store, top_k=5, tactic_filter=next_tactic)
            for t in techs:
                if t.technique_id not in seen_ids:
                    candidates.append(t)
                    seen_ids.add(t.technique_id)
        
        scored_candidates = []
        severity_weight = {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.45}
        p_severity = severity_weight.get(signal.severity.lower(), 0.5)
        
        for candidate in candidates:
            similarity = self._get_similarity_score(candidate.technique_id, signal.raw_event)
            p_semantic = similarity
            
            p_platform = 1.0 if any("Windows" in p for p in candidate.platforms) else 0.7
            
            raw_score = p_semantic * p_platform * p_severity
            scored_candidates.append((candidate, raw_score, similarity))
            
        scored_candidates.sort(key=lambda x: x[1], reverse=True)
        scored_candidates = scored_candidates[:self.max_predictions]

        total_score = sum(score for _, score, _ in scored_candidates)
        normalized_candidates = []
        if total_score > 0:
            for candidate, raw_score, similarity in scored_candidates:
                norm_prob = raw_score / total_score
                if norm_prob >= self.prune_threshold:
                    normalized_candidates.append((candidate, norm_prob, similarity))
        
        moves = []
        for candidate, norm_prob, similarity in normalized_candidates:
            reasoning = f"Following {tactic}, attackers commonly proceed to {candidate.tactic} via {candidate.name}. Semantic similarity to observed signal: {similarity:.2f}"
            
            det_text = candidate.detection[:100] if candidate.detection else "MITRE ATT&CK page for detection guidance"
            defender_action = f"Hunt for {candidate.name} indicators. Review {det_text}"
            
            splunk_query = f'index=botsv3 | search "{candidate.name}" OR "{candidate.technique_id}"'
            
            move = PredictedMove(
                technique_id=candidate.technique_id,
                technique_name=candidate.name,
                tactic=candidate.tactic,
                probability=norm_prob,
                reasoning=reasoning,
                prerequisite_met=True,
                defender_action=defender_action,
                splunk_hunting_query=splunk_query
            )
            moves.append(move)
            
        moves.sort(key=lambda m: m.probability, reverse=True)
        return moves[:self.max_predictions]

    def _get_similarity_score(self, technique_id: str, query_text: str) -> float:
        embedding = embed_text(query_text)
        res = self.vector_store.query(query_embedding=embedding, n_results=1, where={"technique_id": technique_id})
        if res and res[0].get("distance") is not None:
            dist = res[0].get("distance")
            return max(0.0, 1.0 - dist)
        return 0.5
