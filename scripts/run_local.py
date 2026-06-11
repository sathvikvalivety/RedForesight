import sys
import os
import io

# Force UTF-8 encoding for standard output/error on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', line_buffering=True)

from pathlib import Path
import asyncio
import json
import time

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load dotenv early
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from pydantic import ValidationError

from splunk.mcp_client import SplunkMCPClient
from agent.schemas import ObservedSignal, SplunkContext
from splunk.spl_templates import asset_vulnerability_lookup

console = Console()

async def run():
    results = {"mcp": False, "queries": False, "schemas": False, "chromadb": False, "signal": False}
    
    # Step 1 — Header Panel
    console.print(Panel(
        "[dim]Proof-of-Life Local Run Script[/dim]",
        title="[bold cyan]RedForesight — Phase 1[/bold cyan]",
        border_style="cyan"
    ))
    
    # Step 2 — MCP Health Check
    console.print("\n[bold]Step 2: MCP Health Check[/bold]")
    client = SplunkMCPClient()
    try:
        ok = await client.health_check()
        if not ok:
            console.print("[bold red]✗ MCP Server connection failed[/bold red]")
            console.print("Troubleshooting steps:")
            console.print("- Is Splunk Enterprise running at http://localhost:8000?")
            console.print("- Is the MCP token in .env the encrypted MCP token with audience mcp?")
            console.print("- Is port 8089 accessible from PowerShell?")
            await client.close()
            sys.exit(1)
        console.print("[bold green]✓ MCP Server connected to Splunk[/bold green]")
        results["mcp"] = True
    except httpx.ConnectError as e:
        console.print(f"[bold red]✗ Connect Error:[/bold red] {e}")
        await client.close()
        sys.exit(1)

    # Step 3 — Load Test Signal
    console.print("\n[bold]Step 3: Load Test Signal[/bold]")
    signal_path = Path(__file__).parent.parent / "data" / "sample_signals" / "lsass_dump.json"
    try:
        with open(signal_path, "r") as f:
            signal_data = json.load(f)
        signal = ObservedSignal(**signal_data)
        console.print(f"Loaded Signal ID: [cyan]{signal.signal_id}[/cyan], Host: [yellow]{signal.host}[/yellow], Severity: [red bold]{signal.severity.upper()}[/red bold]")
        console.print(f"[dim]Raw event: {signal.raw_event[:80]}[/dim]")
        results["signal"] = True
    except FileNotFoundError:
        console.print(f"[bold red]✗ Signal file not found at {signal_path}[/bold red]")
    except ValidationError as e:
        console.print(f"[bold red]✗ Validation Error in ObservedSignal:[/bold red] {e}")
    except json.JSONDecodeError as e:
        console.print(f"[bold red]✗ JSON Decode Error:[/bold red] {e}")

    # Step 4 — Concurrent Splunk Context Pull
    console.print(f"\n[bold]Step 4: Pulling Context for {signal.host} (all time for BOTS dataset)[/bold]")
    try:
        context_results = await client.pull_host_context(signal.host, window_minutes=0)
        
        table = Table(box=box.ROUNDED)
        table.add_column("Query", justify="left", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Rows", justify="right")
        table.add_column("Duration", justify="right", style="magenta")
        table.add_column("Note", style="dim")
        
        all_success = True
        total_events = 0
        raw_results_dict = {}
        
        for k, res in context_results.items():
            raw_results_dict[k] = res.model_dump()
            if res.success:
                total_events += res.rows_returned
                note = "No data — fresh Splunk?" if res.rows_returned == 0 else list(res.data[0].keys())[0] if res.data else ""
                table.add_row(k, "[green]OK[/green]", str(res.rows_returned), f"{res.duration_ms:.0f}ms", note)
            else:
                all_success = False
                error_msg = res.error[:60] if res.error else "Unknown Error"
                table.add_row(k, "[red]FAIL[/red]", "0", f"{res.duration_ms:.0f}ms", error_msg)
        
        console.print(table)
        console.print(f"Total events retrieved: {total_events}")
        if total_events == 0:
            console.print("[yellow]⚠ No events found. Have you loaded the BOTS v3 dataset?[/yellow]")
            
        if all_success:
            results["queries"] = True
    except httpx.TimeoutException as e:
        console.print(f"[bold red]✗ Queries timed out:[/bold red] {e}")
        raw_results_dict = {}

    # Step 5 — Assemble SplunkContext
    console.print("\n[bold]Step 5: Assemble SplunkContext[/bold]")
    try:
        context = SplunkContext(
            host=signal.host,
            query_window_minutes=0,
            process_events=context_results.get("process_events").data if context_results.get("process_events") and context_results.get("process_events").success else [],
            auth_events=context_results.get("auth_events").data if context_results.get("auth_events") and context_results.get("auth_events").success else [],
            network_events=context_results.get("network_events").data if context_results.get("network_events") and context_results.get("network_events").success else [],
            host_summary=context_results.get("host_summary").data if context_results.get("host_summary") and context_results.get("host_summary").success else [],
            raw_results=raw_results_dict
        )
        console.print(f"Context assembled: total_events={context.total_events}, has_data={context.has_data}")
        results["schemas"] = True
    except ValidationError as e:
        console.print(f"[bold red]✗ SplunkContext Validation Error:[/bold red] {e}")
        context = None

    # Step 6 — Asset Vulnerability Lookup
    console.print("\n[bold]Step 6: Asset Vulnerability Lookup[/bold]")
    vuln_query = asset_vulnerability_lookup(signal.host)
    vuln_res = await client.search(vuln_query, earliest="-1s")
    if vuln_res.success and vuln_res.rows_returned > 0 and vuln_res.data:
        row = vuln_res.data[0]
        if context:
            try:
                context.asset_vulnerability_score = float(row.get("cvss_score", 0.0))
            except ValueError:
                context.asset_vulnerability_score = None
            context.asset_criticality = row.get("asset_criticality")
            context.asset_owner = row.get("owner")
            
        v_table = Table(show_header=False, box=None)
        v_table.add_column(style="cyan")
        v_table.add_column()
        v_table.add_row("Host", signal.host)
        v_table.add_row("CVSS Score", str(row.get("cvss_score")))
        v_table.add_row("Criticality", str(row.get("asset_criticality")))
        v_table.add_row("Owner", str(row.get("owner")))
        console.print(v_table)
    else:
        console.print("[yellow]⚠ Asset lookup returned 0 rows. This is expected on fresh Splunk without vulnerability_scores lookup defined.[/yellow]")

    # Step 7 — ChromaDB Reachability
    console.print("\n[bold]Step 7: ChromaDB Reachability[/bold]")
    try:
        r = httpx.get("http://localhost:8001/api/v2/heartbeat", timeout=5.0)
        if r.status_code == 200:
            console.print("[bold green]✓ ChromaDB running[/bold green]")
            results["chromadb"] = True
        else:
            console.print(f"[bold red]✗ ChromaDB returned status {r.status_code}[/bold red]")
    except httpx.ConnectError:
        console.print("[bold red]✗ ChromaDB not reachable — run: docker-compose up -d[/bold red]")

    # Step 8 — Error Path Verification
    console.print("\n[bold]Step 8: Error Path Verification[/bold]")
    err_res = await client.search("this is not valid SPL !@#$%")
    if not err_res.success:
        error_msg = err_res.error[:60] if err_res.error else "Unknown"
        console.print(f"[bold green]✓ Error handling works:[/bold green] {error_msg}")
    else:
        console.print("[bold yellow]⚠ Unexpected: bad SPL returned success=True[/bold yellow]")

    # Step 9 — Final Summary Panel
    await client.close()
    
    status_grid = []
    status_grid.append(f"MCP Server:   {'[bold green]✓ Connected[/bold green]' if results['mcp'] else '[bold red]✗ Not running[/bold red]'}")
    status_grid.append(f"SPL Queries:  {'[bold green]✓ Executed (4 concurrent)[/bold green]' if results['queries'] else '[bold red]✗ Failed[/bold red]'}")
    status_grid.append(f"Schemas:      {'[bold green]✓ Validated[/bold green]' if results['schemas'] else '[bold red]✗ Failed[/bold red]'}")
    status_grid.append(f"ChromaDB:     {'[bold green]✓ Running[/bold green]' if results['chromadb'] else '[bold red]✗ Not running[/bold red]'}")
    status_grid.append(f"Signal Load:  {'[bold green]✓ ObservedSignal parsed[/bold green]' if results['signal'] else '[bold red]✗ Failed[/bold red]'}")
    
    status_text = "\n".join(status_grid) + "\n\nReady to proceed to Phase 2 — MITRE ATT&CK Brain"
    
    console.print()
    console.print(Panel(
        status_text,
        title="[bold green]Phase 1 Complete[/bold green]",
        border_style="green"
    ))

if __name__ == "__main__":
    asyncio.run(run())
