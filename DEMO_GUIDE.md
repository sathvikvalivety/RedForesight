# RedForesight — Demo & Presentation Guide

## What RedForesight does (one-line pitch)

RedForesight is an AI agent that thinks like an attacker — it reads a partial attack signal from Splunk, predicts the adversary's next MITRE ATT&CK move *before they make it*, and hands the SOC analyst a ready-to-run SPL hunting query for each prediction.

---

## Live demo script (5–8 minutes)

### Prerequisites (already running on this machine)
- **Splunk Enterprise** (Docker) — http://localhost:8000  |  admin / `RedForesight123!`
- **ChromaDB** (Docker) — localhost:8001  (697 MITRE techniques + 16 episodic memories seeded)
- **Ollama** — localhost:11434  (model: `qwen2.5-coder:7b`)
- **FastAPI agent** — localhost:8080  (API key: `redforesight_demo_key_2026`)
- **RedForesight Splunk app** — installed, 4 dashboard views live

### Step 1 — Open Splunk and the RedForesight app (30s)
1. Browser → http://localhost:8000
2. Login: admin / RedForesight123!
3. Left nav → **RedForesight** app (red icon)
4. You land on **▶ Trigger Attack** — the first of 4 tabs.

### Step 2 — Fire an attack signal (1 min)
On the Trigger Attack tab:
- Scenario: **LSASS Credential Dump (T1003.001)** (default)
- Host: BSTOLL-L, Severity: High
- Click **▶ Fire Signal to Agent**

What happens behind the scenes:
1. The dashboard JS POSTs to FastAPI `/api/v1/trigger`.
2. The LangGraph orchestrator runs: ingest → pull Splunk context → classify tactic → expand game-tree → LLM re-score → generate brief → write to Splunk via HEC.
3. The status line shows "✓ Prediction ready" in ~5–10 seconds.

### Step 3 — Show the prediction (1 min)
Switch to the **🎯 Predictions** tab:
- The **Recent Defender Briefs** table shows the new brief: signal, tactic (Credential Access), predicted TTP, probability, confidence, and the LLM's reasoning.
- The **All Ranked Predictions** table expands every predicted next move with its SPL hunting query.
- Top prediction: **T1069.001 Local Groups (Discovery)** at ~50% probability — the agent reasoned "after credential dumping, local group enumeration identifies privilege boundaries and targets for lateral movement."

### Step 4 — Verification & feedback (1 min)
Switch to **✓ Verification & Feedback**:
- The episodes table (polled from ChromaDB via FastAPI) lists all incidents in memory.
- Copy the Episode ID from the new brief.
- Paste it into the feedback form, set Confirmed Technique = T1069.001, Outcome = True.
- Click **Submit Feedback** → "Feedback saved" → the episode is now marked confirmed.
- This is the **learning loop**: confirmed predictions calibrate future predictions to this org's attacker patterns.

### Step 5 — Test pipeline overview (30s)
Switch to **⚙ Test Pipeline**:
- Shows prediction volume, tactic distribution, top predicted techniques.
- The runbook panel lists the 4 phase test scripts for reproducibility.

---

## Test results (run before the demo, show the terminal output)

| Phase | What it tests | Result |
|-------|--------------|--------|
| **pytest** (unit) | Classifier, game-tree, memory recall, MCP client — all mocked | 13/13 passed |
| **Phase 1** | Splunk web/mgmt/HEC, ChromaDB, Ollama connectivity | All 6 checks passed |
| **Phase 2** | MITRE semantic search (T1003, T1021, T1566 found) | All 4 queries passed |
| **Phase 3** | Classifier → game-tree → LLM re-score | Tactic=Credential Access, 5 moves, LLM re-scored T1069.001 to 0.82 |
| **Phase 4** | Webhook trigger → brief → Splunk write → feedback loop | Brief written to Splunk, feedback recorded |

Run them yourself:
```
.\venv\Scripts\activate
python scripts/run_local.py          # Phase 1
python scripts/run_phase2_test.py    # Phase 2
python scripts/run_phase3_test.py    # Phase 3
python -m pytest                     # Unit tests
```

---

## Architecture talking points for the professor

1. **Why prediction, not just detection?** The average detection gap is 197 days. RedForesight compresses the "what happened?" backward investigation into a forward "here's what happens next" — cutting response time from minutes to seconds.

2. **MITRE ATT&CK as memory, not just a taxonomy.** 697 techniques are embedded into ChromaDB using sentence-transformers (`all-MiniLM-L6-v2`). The classifier does semantic search over this vector store to identify the observed tactic, and the game-tree expands only *subsequent* kill-chain tactics — so predictions are structurally constrained to plausible next steps.

3. **Game-tree + LLM hybrid scoring.** The game-tree produces candidates using semantic similarity × platform match × severity weight (a structured prior). The LLM (Ollama, local) then re-scores them with adversarial reasoning. This is a deliberate design choice: the structured prior prevents hallucination, and the LLM adds context-aware probability calibration.

4. **Episodic memory = the feedback loop.** Every prediction is stored as an episode in ChromaDB. When the analyst confirms/rejects, the episode is updated. Over time, `recall_similar` pulls these confirmed patterns, so the agent learns this organization's specific attacker behavior — not just global MITRE frequencies.

5. **Splunk-native.** Predictions are written back to Splunk as JSON events via HEC (sourcetype `_json`, source `redforesight_agent`). The dashboard queries them with standard SPL — no external UI dependency. The app is packaged as a standard Splunk app (`redforesight_app.tgz`).

6. **Local LLM for air-gapped SOC.** Using Ollama with `qwen2.5-coder:7b` means no data leaves the network — important for security operations centers that can't send attack signals to cloud LLMs.

---

## If the professor asks hard questions

**Q: How accurate are the predictions?**
A: The game-tree constrains predictions to subsequent kill-chain tactics (structural correctness), and the LLM re-scores based on the observed signal + environment context. The feedback loop is what drives accuracy improvement over time — each confirmed/rejected episode calibrates future recall. With 15 seeded episodes, recall already returns relevant historical patterns.

**Q: Why not just use Splunk's built-in correlation searches?**
A: Correlation searches detect *what happened*. RedForesight predicts *what happens next* and generates the hunting query proactively. It's complementary — correlation searches feed signals in, RedForesight predicts forward.

**Q: What's the MITRE MCP Server dependency?**
A: The original design uses the Splunk MCP Server (Splunkbase app 7553) for JSON-RPC tool calls. In this setup, since the MCP app isn't installed, the alert writer falls back to direct HEC + REST API, which works identically for writing predictions back. The MCP path is for read-side context queries.

**Q: How does this scale?**
A: ChromaDB is the vector store (horizontal scaling via Docker). The agent is stateless per-invocation (FastAPI background task). The LLM is the bottleneck (~2s per scoring call with qwen2.5-coder:7b on this GPU); a larger model or cloud LLM would improve reasoning quality at the cost of latency/data egress.

---

## File map (if they want to see code)

- Agent core: `agent/orchestrator.py` (LangGraph state machine), `agent/game_tree.py`, `agent/classifier.py`, `agent/llm_client.py`
- Memory: `memory/semantic.py` (MITRE), `memory/episodic.py` (incidents), `memory/vector_store.py` (ChromaDB)
- Splunk: `splunk/mcp_client.py` (JSON-RPC), `splunk/alert_writer.py` (HEC), `splunk/spl_templates.py` (SPL generation)
- API: `api/main.py` (FastAPI), `api/webhook.py` (trigger), `api/feedback.py` (learning loop)
- Dashboard: `dashboard/redforesight_app/` (4 views + JS + app.conf)
- Tests: `tests/` (13 unit tests), `scripts/run_phase*.py` (integration)
