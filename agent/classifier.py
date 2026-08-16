from agent.memory import AgentMemory
from agent.schemas import ObservedSignal

TACTIC_ID_MAP = {
    "Credential Access":     "TA0006",
    "Lateral Movement":      "TA0008",
    "Initial Access":        "TA0001",
    "Execution":             "TA0002",
    "Persistence":           "TA0003",
    "Privilege Escalation":  "TA0004",
    "Defense Evasion":       "TA0005",
    "Discovery":             "TA0007",
    "Collection":            "TA0009",
    "Exfiltration":          "TA0010",
    "Command and Control":   "TA0011",
    "Impact":                "TA0040",
    "Reconnaissance":        "TA0043",
    "Resource Development":  "TA0042",
}

class TacticClassifier:
    def __init__(self, agent_memory: AgentMemory):
        self.agent_memory = agent_memory

    async def classify(self, signal: ObservedSignal) -> tuple[str, str, float]:
        # Query text combining raw event and event type
        query_text = f"{signal.raw_event} {signal.event_type}"
        
        # We need a modified signal to pass to recall, or just pass the existing signal since
        # the orchestrator doesn't need to change it, it just uses signal.raw_event.
        # Wait, AgentMemory.recall uses signal.raw_event as the search query.
        # But here we want to search using "raw_event + event_type".
        # Let's create a temporary signal for the query just to satisfy AgentMemory interface,
        # or just modify the raw_event locally.
        temp_signal = signal.model_copy()
        temp_signal.raw_event = query_text
        
        # Call agent_memory.recall to get top 5 techniques
        recall_result = await self.agent_memory.recall(temp_signal, tactic_hint=None)
        techniques = recall_result.get("techniques", [])
        
        if not techniques:
            return ("Unknown", "TA0000", 0.0)
            
        top_tactic = techniques[0].tactic
        tactic_id = TACTIC_ID_MAP.get(top_tactic, "TA0000")
        
        # Count how many of the returned techniques share the top tactic
        same_tactic_count = sum(1 for t in techniques if t.tactic == top_tactic)
        confidence = same_tactic_count / len(techniques)
        
        return (top_tactic, tactic_id, float(confidence))
