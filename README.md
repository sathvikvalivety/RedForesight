# RedForesight

An AI agent that thinks like an attacker — predicting your adversary's next move before they make it, using MITRE ATT&CK and Splunk memory.

RedForesight reads partial attack signals, loads historical MITRE ATT&CK playbooks into memory, and generates a probability-ranked set of next attacker moves. It uses a LangGraph state machine, ChromaDB for semantic and episodic memory, and connects directly to Splunk via an MCP Server.

## Who is this for?

**Primary — Security Operations Center (SOC) Analysts**
These are the people staring at Splunk dashboards at 2am. Their daily reality is alert fatigue — hundreds of notifications, most of them noise, and the real attacks hidden in the middle. When a genuine threat signal fires, they spend 20–30 minutes manually investigating backward: what happened, which host, which user, which process.
RedForesight cuts that backward investigation time and replaces it with forward prediction. Instead of the analyst asking "what happened here?", RedForesight immediately answers "here is what happens next, here is the SPL query to hunt for it right now, and here is what to block."
The feedback loop means the tool gets better the longer a SOC uses it. After 100 confirmed predictions, RedForesight knows the specific attacker patterns that appear in that organization's environment — not just global MITRE ATT&CK frequencies.

**Secondary — Threat Hunters**
Threat hunters proactively look for attackers already inside the network rather than waiting for alerts. Their biggest challenge is knowing where to look. RedForesight gives them a prioritized hypothesis list — given what was observed on this host, these are the three most likely next actions the attacker took, ranked by probability, each with a ready-made SPL query.
It converts a vague "go hunt for lateral movement" directive into a specific "run this query against these hosts looking for this technique" instruction.

**Tertiary — Security Engineers Building on Splunk**
Any team building AI-powered security applications on the Splunk platform can use RedForesight as a reference architecture. It demonstrates:
- How to connect an AI agent to Splunk via the MCP Server using JSON-RPC 2.0
- How to combine semantic search over MITRE ATT&CK with episodic memory from past incidents
- How to use LangGraph for typed, testable agent orchestration
- How to write predicted threat intelligence back into Splunk via HEC for querying

## The Scale of the Problem
Every organization running Splunk Enterprise or Splunk Cloud is a potential user. The detection gap — the time between when an attacker executes a technique and when a defender responds — averages 197 days according to industry research. RedForesight attacks that gap directly.
The memory system means the value compounds over time. An organization that runs RedForesight for six months has an agent calibrated to their specific attacker patterns, their specific infrastructure, and their specific vulnerability profile. That is genuinely difficult to replicate with generic rule-based detection.

## Prerequisites

- Splunk Enterprise (Trial or Developer license)
- Docker & Docker Compose (for ChromaDB)
- Python 3.9+

---

## Installation & Setup Guide

### 1. Installing Splunk

You can run Splunk Enterprise locally or use the official Docker image. To quickly start a local instance using Docker:

```bash
docker run -d -p 8000:8000 -p 8089:8089 -e "SPLUNK_START_ARGS=--accept-license" -e "SPLUNK_PASSWORD=YourStrongPassword" --name splunk splunk/splunk:latest
```

Once running, access the Splunk Web Interface at `http://localhost:8000`. Log in with username `admin` and the password you set.

### 2. Loading the BOTSv3 Dataset into Splunk

This project uses the BOTSv3 (Boss of the SOC version 3) dataset for realistic threat signals. You can download the dataset from the official [Splunk BOTSv3 repository](https://github.com/splunk/botsv3) or use the provided `botsv3_data_set.tgz`.

To ingest this data into your Splunk instance:
1. Log in to Splunk Web.
2. Go to **Settings** > **Add Data**.
3. Select **Upload** and choose the `botsv3_data_set.tgz` file.
   *(Note: Depending on the archive structure, you may need to extract it first and upload the raw log or JSON files).*
4. Click **Next** and configure the source type. If the data is JSON, ensure the source type is set to `_json`.
5. For the **Index**, you can leave it as `default` (which uses `main`), or create a new index named `botsv3`. If you create a new index, ensure you update the Splunk searches in `splunk/spl_templates.py` to target `index=botsv3`.
6. Review your settings and click **Submit**.

### 3. Installing the Splunk MCP Server

The Splunk MCP (Model Context Protocol) Server acts as the connective tissue between the AI agent and your live Splunk data. You can download it from [Splunkbase](https://splunkbase.splunk.com/app/7553/) (search for "Splunk MCP Server") or use the packaged Splunk App in `splunk-mcp-server_120.tgz`.

To add the MCP Server to Splunk:
1. In Splunk Web, click the gear icon next to **Apps** (Manage Apps) on the top left.
2. Click **Install app from file**.
3. Click **Choose File** and select `splunk-mcp-server_120.tgz` from the project root directory.
4. Check **Upgrade app** if you are reinstalling, then click **Upload**.
5. Splunk will prompt you to restart. Click **Restart Now**.

Once Splunk reboots, the MCP server will be active. Make sure to generate an authentication token in Splunk (Settings > Tokens) for your `mcp_client.py` to authenticate securely.

### 4. Installing or Updating the RedForesight Dashboard

If you make any changes to the `.xml` dashboard files in `dashboard/redforesight_app` (or are installing it for the first time), you must package the folder into a `.tgz` archive and upload it to Splunk:

1. Navigate to the `dashboard` directory:
   ```bash
   cd dashboard
   ```
2. Create the `.tgz` archive (using `tar`, available natively on macOS, Linux, and Windows 10+):
   ```bash
   tar -czvf redforesight_app.tgz redforesight_app
   ```
3. In Splunk Web, go to **Manage Apps** (gear icon) > **Install app from file**.
4. Upload the newly created `redforesight_app.tgz`, check **Upgrade app**, and click **Upload**.

### 5. Setting up the Python Agent Environment

Set up the core RedForesight agent and its memory database:

1. **Create a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Configuration:**
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` to include your Splunk URL, Splunk auth token, and any LLM API keys.

4. **Start ChromaDB (Memory layer):**
   ```bash
   # We use local chroma to persist our seeded data
   .\venv\Scripts\chroma.exe run --path db --port 8001
   ```
   This spins up ChromaDB on port 8001, which is used for both episodic memory (past attacker paths) and semantic memory (MITRE ATT&CK techniques).

### 6. Starting the Project

To start a new development session or run RedForesight, you must start the required services in the following order:

**1. Start Splunk Enterprise**
Ensure your Splunk instance (Docker or local) is running at `http://localhost:8000` and the MCP server is installed.

**2. Start ChromaDB (Memory Layer)**
In a new terminal, activate your virtual environment and start ChromaDB on port 8001:
```powershell
cd E:\RedForesight
venv\Scripts\activate
.\venv\Scripts\chroma.exe run --path db --port 8001
```

**3. Run RedForesight (Choose an option)**
With Splunk and ChromaDB running, open a new terminal, activate the `venv`, and choose how to run the agent:

*Option A: Start the FastAPI Server (For UI and Webhooks)*
To run the full agent with the interactive dashboard and webhook capabilities:
```bash
uvicorn api.main:app --reload
```
The API will be available at `http://localhost:8000` (or your uvicorn port). This powers the Splunk dashboard's prediction and feedback workflows.

*Option B: Run the Local Verification Script*
To simply test that your environment is correctly configured (proof-of-life):
```bash
python scripts/run_local.py
```
This fires a test signal, queries Splunk via MCP, and validates that all components are communicating properly.

---

## Recent Updates & Bug Fixes

We've recently introduced several key improvements to RedForesight:

**Security Enhancements**
- **SPL Injection Prevention**: Added strict sanitization to `spl_templates.py` to prevent potential SPL injection attacks when querying Splunk.
- **MCP Client Security**: Enabled SSL verification (`verify=True`) in the MCP HTTP client to ensure secure communication with Splunk.

**Core Agent & Memory Improvements**
- **Memory Management**: Refactored episodic memory to reuse embeddings natively, drastically reducing compute overhead.
- **Semantic Memory Parsing**: Improved parsing of MITRE ATT&CK techniques, reliably extracting descriptions and detection logic.
- **Timezone Safety**: Replaced deprecated `datetime.utcnow()` with timezone-aware `datetime.now(timezone.utc)` for writing alerts into Splunk.

**UI & Feature Additions**
- **Interactive Dashboard**: Added a new UI dashboard for RedForesight Predictions and Feedback.
- **FastAPI Endpoints**: Deployed a dedicated API via FastAPI along with complete test coverage for LLM client integration and endpoint validation.
- **Dependency Optimization**: Cleaned up the Python agent dependencies to ensure `langgraph` and `cachetools` operate smoothly.
