# RedForesight

An AI agent that thinks like an attacker — predicting your adversary's next move before they make it, using MITRE ATT&CK and Splunk memory.

RedForesight reads partial attack signals, loads historical MITRE ATT&CK playbooks into memory, and generates a probability-ranked set of next attacker moves. It uses a LangGraph state machine, ChromaDB for semantic and episodic memory, and connects directly to Splunk via an MCP Server.

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

This project uses the BOTSv3 (Boss of the SOC version 3) dataset for realistic threat signals. The dataset is provided in `botsv3_data_set.tgz`.

To ingest this data into your Splunk instance:
1. Log in to Splunk Web.
2. Go to **Settings** > **Add Data**.
3. Select **Upload** and choose the `botsv3_data_set.tgz` file.
   *(Note: Depending on the archive structure, you may need to extract it first and upload the raw log or JSON files).*
4. Click **Next** and configure the source type. If the data is JSON, ensure the source type is set to `_json`.
5. For the **Index**, you can leave it as `default` (which uses `main`), or create a new index named `botsv3`. If you create a new index, ensure you update the Splunk searches in `splunk/spl_templates.py` to target `index=botsv3`.
6. Review your settings and click **Submit**.

### 3. Installing the Splunk MCP Server

The Splunk MCP (Model Context Protocol) Server acts as the connective tissue between the AI agent and your live Splunk data. We have packaged it as a Splunk App in `splunk-mcp-server_120.tgz`.

To add the MCP Server to Splunk:
1. In Splunk Web, click the gear icon next to **Apps** (Manage Apps) on the top left.
2. Click **Install app from file**.
3. Click **Choose File** and select `splunk-mcp-server_120.tgz` from the project root directory.
4. Check **Upgrade app** if you are reinstalling, then click **Upload**.
5. Splunk will prompt you to restart. Click **Restart Now**.

Once Splunk reboots, the MCP server will be active. Make sure to generate an authentication token in Splunk (Settings > Tokens) for your `mcp_client.py` to authenticate securely.

### 4. Setting up the Python Agent Environment

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

### Development Setup (Startup Sequence)

Every development session from here needs this exact startup order:

```powershell
# 1. Start ChromaDB (local)
.\venv\Scripts\chroma.exe run --path db --port 8001

# 2. Activate venv (new terminal)
cd E:\RedForesight
venv\Scripts\activate

# 3. Verify Splunk is running at http://localhost:8000
```

### 5. Running the Agent

With Splunk, the MCP Server, and ChromaDB running, you can test the agent locally:

```bash
python scripts/run_local.py
```

This will fire a test signal (e.g., from `data/sample_signals/lsass_dump.json`) through the orchestrator, query Splunk via the MCP server for context, and output a ranked list of predicted next moves based on MITRE ATT&CK profiles and episodic memory.
