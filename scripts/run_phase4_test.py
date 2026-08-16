import asyncio
import httpx
import logging
import sys
import os
from uuid import uuid4
from datetime import datetime, timezone
from rich.console import Console

# Add project root to PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent.llm_client import LLMClient
from agent.schemas import ObservedSignal, SplunkContext, PredictedMove
from splunk.alert_writer import AlertWriter

console = Console()
logging.basicConfig(level=logging.ERROR)

async def test_1_llm_client_scores_moves(llm_client):
    console.print("\n[bold cyan]Test 1: LLM client scores moves[/bold cyan]")
    signal = ObservedSignal(
        signal_id=str(uuid4()),
        timestamp=str(datetime.now(timezone.utc)),
        host="TEST-HOST",
        source_ip="10.0.0.1",
        raw_event="rundll32.exe accessed lsass.exe memory",
        event_type="credential_access",
        severity="high",
        splunk_index="main",
        additional_context={}
    )
    context = SplunkContext(host="TEST-HOST", query_window_minutes=30, process_events=[], auth_events=[], network_events=[], host_summary=[], raw_results={})
    moves = [
        PredictedMove(technique_id="T1069.001", technique_name="Local Groups", tactic="Discovery", probability=0.5, reasoning="", confidence_tier="low", prerequisite_met=True, defender_action="", splunk_hunting_query="")
    ]
    
    try:
        scored = await llm_client.score_moves(signal, context, moves)
        assert len(scored) == 1
        console.print("[green]PASS: LLM client returned scored moves[/green]")
        return True
    except Exception as e:
        console.print(f"[red]FAIL: LLM client failed: {e}[/red]")
        return False

async def test_2_llm_rescoring_changes_probs(llm_client):
    console.print("\n[bold cyan]Test 2: LLM re-scoring changes probabilities[/bold cyan]")
    signal = ObservedSignal(
        signal_id=str(uuid4()),
        timestamp=str(datetime.now(timezone.utc)),
        host="TEST-HOST",
        source_ip="10.0.0.1",
        raw_event="lsass.exe memory dump",
        event_type="credential_access",
        severity="high",
        splunk_index="main",
        additional_context={}
    )
    context = SplunkContext(host="TEST-HOST", query_window_minutes=30, process_events=[], auth_events=[], network_events=[], host_summary=[], raw_results={})
    moves = [
        PredictedMove(technique_id="T1069.001", technique_name="Local Groups", tactic="Discovery", probability=0.1, reasoning="", confidence_tier="low", prerequisite_met=True, defender_action="", splunk_hunting_query="")
    ]
    
    try:
        scored = await llm_client.score_moves(signal, context, moves)
        assert scored[0].probability != 0.1, "Probability did not change"
        assert scored[0].reasoning != "", "Reasoning was not provided"
        console.print("[green]PASS: LLM re-scoring successfully changed probabilities[/green]")
        return True
    except Exception as e:
        console.print(f"[red]FAIL: LLM re-scoring failed: {e}[/red]")
        return False

async def test_3_alert_writer_connectivity(alert_writer):
    console.print("\n[bold cyan]Test 3: Alert writer connectivity[/bold cyan]")
    try:
        # We just write a simple dict to trigger fallback or real REST/HEC
        res = await alert_writer.write_brief({"test": "connectivity"})
        assert res is True
        console.print(f"[green]PASS: Alert writer connected and wrote event. Write method: {alert_writer.write_method}[/green]")
        return True
    except Exception as e:
        console.print(f"[red]FAIL: Alert writer failed: {e}[/red]")
        return False

async def test_4_fastapi_health(api_client):
    console.print("\n[bold cyan]Test 4: FastAPI health endpoint[/bold cyan]")
    try:
        res = await api_client.get("http://localhost:8080/health")
        assert res.status_code == 200
        console.print("[green]PASS: FastAPI health endpoint returned 200 OK[/green]")
        return True
    except Exception as e:
        console.print(f"[red]FAIL: FastAPI health check failed: {e}[/red]")
        return False

async def test_5_webhook_trigger(api_client):
    console.print("\n[bold cyan]Test 5: Webhook trigger[/bold cyan]")
    payload = {
        "host": "TEST-WEBHOOK",
        "event_type": "test_event",
        "raw_event": "test signal",
        "severity": "low"
    }
    try:
        res = await api_client.post("http://localhost:8080/api/v1/trigger", json=payload)
        assert res.status_code == 202
        data = res.json()
        task_id = data.get("task_id") or data.get("signal_id")
        console.print(f"[green]PASS: Webhook trigger successful, task_id: {task_id}[/green]")
        return task_id
    except Exception as e:
        console.print(f"[red]FAIL: Webhook trigger failed: {e}[/red]")
        return None

async def test_6_feedback_endpoint(api_client):
    console.print("\n[bold cyan]Test 6: Feedback endpoint[/bold cyan]")
    
    # 1. Test 404 on fake ID
    fake_payload = {
        "episode_id": str(uuid4()),
        "confirmed_technique_id": "T1003",
        "outcome_confirmed": True
    }
    try:
        res_404 = await api_client.post("http://localhost:8080/api/v1/feedback", json=fake_payload)
        assert res_404.status_code == 404, f"Expected 404, got {res_404.status_code}"
        
        # 2. Test 200 on real ID
        res_eps = await api_client.get("http://localhost:8080/api/v1/feedback/episodes")
        episodes = res_eps.json().get("episodes", [])
        if not episodes:
            console.print("[yellow]WARN: No episodes found to test 200 response. Did you seed?[/yellow]")
            return True
            
        real_payload = {
            "episode_id": episodes[0]["id"],
            "confirmed_technique_id": "T1003",
            "outcome_confirmed": True
        }
        res_200 = await api_client.post("http://localhost:8080/api/v1/feedback", json=real_payload)
        assert res_200.status_code == 200, f"Expected 200, got {res_200.status_code}"
        console.print("[green]PASS: Feedback endpoint correctly handled 404 and 200 cases[/green]")
        return True
    except Exception as e:
        console.print(f"[red]FAIL: Feedback endpoint failed: {e}[/red]")
        return False

async def test_7_episodic_memory_influence():
    from agent.memory import AgentMemory
    mem = AgentMemory()
    count = mem.episodic_store.count()
    signal = ObservedSignal(
        signal_id=str(uuid4()),
        timestamp=str(datetime.now(timezone.utc)),
        host='BSTOLL-L',
        source_ip='10.0.0.1',
        raw_event='rundll32.exe accessed lsass.exe memory GrantedAccess 0x1010',
        event_type='credential_access_attempt',
        severity='high',
        splunk_index="main",
        additional_context={}
    )
    result = await mem.recall(signal)
    episode_count = len(result['episodes'])
    assert count >= 15, f"Expected >= 15 seeded episodes, got {count}"
    assert episode_count >= 1, f"Expected recall to return episodes, got {episode_count}"
    console.print(f"[green]PASS: {count} episodes in memory, recall returned {episode_count}[/green]")
    return True

async def test_8_end_to_end_loop(api_client, task_id):
    console.print("\n[bold cyan]Test 8: Full end-to-end loop[/bold cyan]")
    if not task_id:
        console.print("[yellow]WARN: Skipping end-to-end test because webhook trigger failed.[/yellow]")
        return False
        
    try:
        # Poll for completion
        status = "unknown"
        for _ in range(10):
            res = await api_client.get(f"http://localhost:8080/api/v1/trigger/status/{task_id}")
            if res.status_code == 200:
                status = res.json().get("status")
            if status in ["completed", "failed"]:
                break
            await asyncio.sleep(2)
            
        console.print(f"[cyan]Final status received from endpoint: '{status}'[/cyan]")
        assert status == "completed", f"Task ended with status: {status}"
        console.print("[green]PASS: End-to-end webhook loop completed successfully[/green]")
        return True
    except Exception as e:
        console.print(f"[red]FAIL: End-to-end loop failed: {e}[/red]")
        return False

async def main():
    llm_client = LLMClient()
    alert_writer = AlertWriter()
    api_client = httpx.AsyncClient(timeout=10.0)
    
    passed = 0
    total = 8
    
    r1 = await test_1_llm_client_scores_moves(llm_client)
    r2 = await test_2_llm_rescoring_changes_probs(llm_client)
    r3 = await test_3_alert_writer_connectivity(alert_writer)
    r4 = await test_4_fastapi_health(api_client)
    r5 = await test_5_webhook_trigger(api_client)
    r6 = await test_6_feedback_endpoint(api_client)
    r7 = await test_7_episodic_memory_influence()
    r8 = await test_8_end_to_end_loop(api_client, r5)
    
    for r in [r1, r2, r3, r4, bool(r5), r6, r7, r8]:
        if r: passed += 1
        
    console.print(f"\n[bold]{passed}/{total} tests passed.[/bold]")
    
    await llm_client.close()
    await alert_writer.close()
    await api_client.aclose()

if __name__ == "__main__":
    asyncio.run(main())
