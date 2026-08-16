import asyncio
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table

from agent.schemas import ObservedSignal, SplunkContext
from agent.memory import AgentMemory
from agent.classifier import TacticClassifier
from agent.game_tree import GameTree
from agent.orchestrator import run_agent
from splunk.mcp_client import SplunkMCPClient
from agent.llm_client import LLMClient
from memory.vector_store import VectorStore

async def main():
    console = Console()
    console.print("\n[bold blue]Running Phase 3 Tests...[/bold blue]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Test ID", style="dim", width=8)
    table.add_column("Description", width=50)
    table.add_column("Status", justify="center")
    
    # Initialize components
    mem = AgentMemory()
    vs = VectorStore("localhost", 8001, "mitre_techniques")
    client = SplunkMCPClient()
    clf = TacticClassifier(mem)
    gt = GameTree(mem, vs)
    llm = LLMClient()
    
    lsass_signal = ObservedSignal(
        signal_id="SIG-LSASS",
        timestamp=str(datetime.now(timezone.utc)),
        host="BSTOLL-L",
        source_ip="10.0.0.1",
        raw_event="rundll32.exe accessed lsass.exe memory GrantedAccess 0x1010",
        event_type="credential_access_attempt",
        severity="high",
        splunk_index="botsv3",
        additional_context={}
    )
    
    phishing_signal = ObservedSignal(
        signal_id="SIG-PHISH",
        timestamp=str(datetime.now(timezone.utc)),
        host="USER-PC",
        source_ip="192.168.1.5",
        raw_event="User clicked on malicious link in email payload.exe",
        event_type="phishing",
        severity="medium",
        splunk_index="botsv3",
        additional_context={}
    )
    
    context = SplunkContext(
        host="BSTOLL-L", 
        query_window_minutes=30,
        process_events=[],
        auth_events=[],
        network_events=[],
        host_summary=[],
        raw_results={}
    )
    
    def pass_fail(condition: bool):
        return "[bold green]Pass[/bold green]" if condition else "[bold red]Fail[/bold red]"
    
    # Test 1: classifier.classify() on LSASS signal
    tactic, tid, conf = await clf.classify(lsass_signal)
    t1_pass = (tactic == "Credential Access")
    table.add_row("Test 1", "Classifier LSASS -> Credential Access", pass_fail(t1_pass))
    
    # Test 2: classifier.classify() on phishing signal
    tactic_p, tid_p, conf_p = await clf.classify(phishing_signal)
    t2_pass = (tactic_p in ["Initial Access", "Execution"])
    table.add_row("Test 2", "Classifier Phishing -> Initial Access / Execution", pass_fail(t2_pass))
    
    # Test 3: game_tree.expand() size and probs
    moves = await gt.expand(lsass_signal, "Credential Access", context)
    total_prob = sum(m.probability for m in moves)
    t3_pass = len(moves) >= 3 and all(m.probability > 0 for m in moves) and 0.95 <= total_prob <= 1.05
    table.add_row("Test 3", "GameTree returns >=3 moves, probabilities sum ~1.0", pass_fail(t3_pass))
    
    # Test 4: game_tree.expand() tactics check
    valid_tactics = {"Lateral Movement", "Discovery", "Collection"}
    t4_pass = all(m.tactic in valid_tactics for m in moves) and len(moves) > 0
    table.add_row("Test 4", "GameTree moves strictly from subsequent kill chain", pass_fail(t4_pass))
    
    # Test 5: run_agent() end-to-end
    initial_episodes = mem.episodic_store.count()
    brief = await run_agent(lsass_signal, client, mem, gt, clf, llm)
    t5_pass = brief is not None and brief.prediction_count > 0 and brief.tactic_classification == "Credential Access"
    table.add_row("Test 5", "Orchestrator generates valid DefenderBrief", pass_fail(t5_pass))
    
    # Test 6: episodic memory updated
    final_episodes = mem.episodic_store.count()
    t6_pass = final_episodes > initial_episodes
    table.add_row("Test 6", "Episodic memory stores incident after brief", pass_fail(t6_pass))
    
    await client.close()
    
    console.print(table)
    print("")

if __name__ == "__main__":
    asyncio.run(main())

