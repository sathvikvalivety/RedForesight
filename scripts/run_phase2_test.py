import sys
import io
import asyncio
from pathlib import Path

# Force UTF-8 encoding for standard output/error on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', line_buffering=True)

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.table import Table

from agent.mitre_loader import load_all_techniques
from memory.vector_store import VectorStore
from memory.semantic import search_techniques, load_embedding_model
from agent.memory import AgentMemory
from agent.schemas import ObservedSignal
from datetime import datetime

console = Console()

async def run_tests():
    console.print("\n[bold]Running Phase 2 Tests...[/bold]\n")
    
    table = Table(title="Phase 2 Tests")
    table.add_column("Test", style="cyan", width=30)
    table.add_column("Status", justify="center")
    table.add_column("Detail")
    
    all_passed = True
    
    def log_result(name, passed, detail):
        nonlocal all_passed
        status = "[bold green]Pass[/bold green]" if passed else "[bold red]Fail[/bold red]"
        if not passed:
            all_passed = False
        table.add_row(name, status, detail)

    bundle_path = Path(__file__).parent.parent / "data" / "mitre_attack.json"
    
    # Test 1
    try:
        techs = load_all_techniques(str(bundle_path))
        if len(techs) > 600:
            log_result("1. STIX bundle load", True, f"Loaded {len(techs)} techniques")
        else:
            log_result("1. STIX bundle load", False, f"Loaded only {len(techs)} techniques")
    except Exception as e:
        log_result("1. STIX bundle load", False, str(e))
        techs = []

    # Test 2
    try:
        vs = VectorStore("localhost", 8001, "mitre_techniques")
        count = vs.count()
        if count == len(techs) and count > 0:
            log_result("2. ChromaDB count", True, f"Count {count} matches seeded techniques")
        else:
            log_result("2. ChromaDB count", False, f"Count {count} != {len(techs)}")
    except Exception as e:
        log_result("2. ChromaDB count", False, str(e))
        
    # Load model for tests 3-6
    load_embedding_model()

    # Test 3
    try:
        results = search_techniques("LSASS dump credential harvesting", vs, top_k=5)
        top3_ids = [r.technique_id for r in results[:3]]
        if any("T1003" in tid for tid in top3_ids):
            log_result("3. Credential access search", True, f"Found T1003 in top 3: {top3_ids}")
        else:
            log_result("3. Credential access search", False, f"T1003 not in top 3: {top3_ids}")
    except Exception as e:
        log_result("3. Credential access search", False, str(e))

    # Test 4
    try:
        results = search_techniques("PsExec remote service execution lateral movement", vs, top_k=5)
        top5_ids = [r.technique_id for r in results]
        if any(tid.startswith("T1021") or tid.startswith("T1570") for tid in top5_ids):
            log_result("4. Lateral movement search", True, f"Found expected in top 5: {top5_ids}")
        else:
            log_result("4. Lateral movement search", False, f"Not found in top 5: {top5_ids}")
    except Exception as e:
        log_result("4. Lateral movement search", False, str(e))

    # Test 5
    try:
        results = search_techniques("phishing email macro Office document", vs, top_k=5)
        top5_ids = [r.technique_id for r in results]
        if any("T1566" in tid for tid in top5_ids):
            log_result("5. Initial access search", True, f"Found T1566 in top 5: {top5_ids}")
        else:
            log_result("5. Initial access search", False, f"T1566 not found in top 5: {top5_ids}")
    except Exception as e:
        log_result("5. Initial access search", False, str(e))

    # Test 6
    try:
        results = search_techniques("process injection", vs, top_k=5, tactic_filter="Defense Evasion")
        tactics = set(r.tactic for r in results)
        if len(tactics) == 1 and list(tactics)[0] == "Defense Evasion":
            log_result("6. Tactic filter", True, "All results are Defense Evasion")
        else:
            log_result("6. Tactic filter", False, f"Found tactics: {tactics}")
    except Exception as e:
        log_result("6. Tactic filter", False, str(e))

    # Test 7
    try:
        mem = AgentMemory()
        signal = ObservedSignal(
            signal_id='1',
            timestamp=str(datetime.utcnow()),
            host='CORP-DC-01',
            source_ip='10.0.0.1',
            raw_event='rundll32.exe accessed lsass.exe memory GrantedAccess 0x1010',
            event_type='credential_access_attempt',
            severity='high',
            splunk_index='main',
            additional_context={}
        )
        res = await mem.recall(signal)
        
        tech_count = len(res["techniques"])
        ep_count = len(res["episodes"])
        
        if tech_count == 5 and ep_count == 0:
            log_result("7. Unified AgentMemory", True, f"Returned 5 techniques, 0 episodes")
        else:
            log_result("7. Unified AgentMemory", False, f"Returned {tech_count} techniques, {ep_count} episodes")
    except Exception as e:
        log_result("7. Unified AgentMemory", False, str(e))

    console.print(table)
    
    if all_passed:
        console.print("\n[bold green]All tests passed! Phase 2 is complete.[/bold green]")
    else:
        console.print("\n[bold red]Some tests failed.[/bold red]")

if __name__ == "__main__":
    asyncio.run(run_tests())
