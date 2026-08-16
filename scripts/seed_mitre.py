import sys
import os
import io
from pathlib import Path

# Force UTF-8 encoding for standard output/error on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', line_buffering=True)

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from collections import Counter
import time
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from agent.mitre_loader import load_all_techniques
from memory.vector_store import VectorStore
from memory.semantic import seed_collection, search_techniques, load_embedding_model

console = Console()

def main():
    force = "--force" in sys.argv
    
    # Step 1 — Check if already seeded
    vs = VectorStore("localhost", 8001, "mitre_techniques")
    current_count = vs.count()
    if current_count > 0 and not force:
        console.print(f"[bold yellow]Collection already seeded with {current_count} techniques. Use --force to re-seed.[/bold yellow]")
        sys.exit(0)
        
    if current_count > 0 and force:
        console.print("[bold red]Resetting existing collection...[/bold red]")
        vs.reset()

    # Step 2 — Load techniques
    console.print("\n[bold]Loading STIX bundle...[/bold]")
    bundle_path = Path(__file__).parent.parent / "data" / "mitre_attack.json"
    techniques = load_all_techniques(str(bundle_path))
    
    tactics = [t.tactic for t in techniques]
    tactic_counts = Counter(tactics)
    
    console.print(f"Loaded {len(techniques)} techniques.")
    
    table = Table(title="Techniques by Tactic")
    table.add_column("Tactic", justify="left", style="cyan")
    table.add_column("Count", justify="right", style="magenta")
    
    for tactic, count in sorted(tactic_counts.items()):
        table.add_row(tactic, str(count))
        
    console.print(table)
    
    # Step 3 — Confirm with user
    # In automated test environments we skip the prompt
    proceed = Prompt.ask("Proceed with embedding?", choices=["y", "N"], default="N")
    if proceed.lower() != "y":
        console.print("Aborted.")
        sys.exit(0)
        
    # Step 4 — Load embedding model
    console.print("\n[bold]Loading embedding model (first load downloads ~90MB)...[/bold]")
    load_embedding_model()
    
    # Step 5 — Seed the collection
    console.print("\n[bold]Seeding collection...[/bold]")
    start_time = time.time()
    total_embedded = seed_collection(techniques, vs)
    elapsed = time.time() - start_time
    
    # Step 6 — Verify
    console.print("\n[bold]Verifying...[/bold]")
    results = search_techniques("credential dumping lsass", vs, top_k=5)
    
    table_res = Table(title="Search Results: 'credential dumping lsass'")
    table_res.add_column("ID", style="cyan")
    table_res.add_column("Name")
    table_res.add_column("Distance", justify="right")
    
    t1003_found = False
    for t in results:
        dist = t.get("distance", 0.0) if isinstance(t, dict) else getattr(t, "distance", 0.0)
        table_res.add_row(t.technique_id, t.name, f"{dist:.4f}")
        if t.technique_id.startswith("T1003"):
            t1003_found = True
            
    console.print(table_res)
    if not t1003_found:
        console.print("[bold red]Warning: T1003 not found in top 5 results![/bold red]")
        
    # Step 7 — Print summary
    console.print(f"\n[bold green]Success![/bold green] Embedded {total_embedded} techniques in {elapsed:.1f}s.")
    console.print(f"ChromaDB Collection: {vs.collection_name}")

if __name__ == "__main__":
    main()
