"""
RedForesight Graph Visualizer - port 8081
No trigger button. Polls ChromaDB directly for episode count changes.
When a new attack is fired from Splunk (port 8000), the episode count increases
and this visualizer animates the pipeline graph live.
"""
import os, sys, asyncio, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI(title="RedForesight Graph Visualizer")
API_BASE = "http://127.0.0.1:8080/api/v1"
API_KEY = os.getenv("API_KEY", "redforesight_demo_key_2026")
CHROMA_COUNT_URL = "http://127.0.0.1:8001/api/v2/tenants/default_tenant/databases/default_database/collections/f22d883d-9af2-4c61-bff0-dc303c191ac8/count"

HTML = open(Path(__file__).parent / "graph_viz.html", "r", encoding="utf-8").read()

@app.get("/")
async def get_page():
    return HTMLResponse(HTML)

async def get_episode_count():
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(CHROMA_COUNT_URL)
            return r.json().get("total_count", 0)
    except Exception:
        return -1

async def get_latest_episode():
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(API_BASE + "/feedback/episodes", headers={"X-API-Key": API_KEY})
            eps = r.json().get("episodes", [])
            return eps[0] if eps else None
    except Exception:
        return None

async def get_splunk_predictions():
    import urllib3
    urllib3.disable_warnings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as sc:
            lr = await sc.post(
                "https://127.0.0.1:8089/services/auth/login",
                data={"username": "admin", "password": "RedForesight123!"},
                timeout=15.0
            )
            if "<sessionKey>" not in lr.text:
                return "Unknown", []
            stoken = lr.text.split("<sessionKey>")[1].split("</sessionKey>")[0]
            sc.headers["Authorization"] = "Bearer " + stoken
            sq = (
                'search index=main sourcetype=_json source=redforesight_agent '
                '| spath tactic_classification '
                '| spath ranked_predictions{}.technique_id as tid '
                '| spath ranked_predictions{}.technique_name as tname '
                '| spath ranked_predictions{}.tactic as ttactic '
                '| spath ranked_predictions{}.probability as tprob '
                '| spath ranked_predictions{}.confidence_tier as tconf '
                '| spath ranked_predictions{}.reasoning as treason '
                '| sort - _time | head 1'
            )
            sr = await sc.post(
                "https://127.0.0.1:8089/services/search/jobs",
                data={"search": sq, "exec_mode": "oneshot", "count": 1, "output_mode": "json"},
                timeout=30.0
            )
            sd = sr.json()
            results = sd.get("results", [])
            if not results:
                return "Unknown", []
            row = results[0]
            tactic_name = row.get("tactic_classification", "Unknown")
            if isinstance(tactic_name, list):
                tactic_name = tactic_name[0] if tactic_name else "Unknown"

            tids = row.get("tid", [])
            if isinstance(tids, str): tids = [tids]
            tnames = row.get("tname", [])
            if isinstance(tnames, str): tnames = [tnames]
            ttactics = row.get("ttactic", [])
            if isinstance(ttactics, str): ttactics = [ttactics]
            tprobs = row.get("tprob", [])
            if isinstance(tprobs, str): tprobs = [tprobs]
            tconfs = row.get("tconf", [])
            if isinstance(tconfs, str): tconfs = [tconfs]
            treasons = row.get("treason", [])
            if isinstance(treasons, str): treasons = [treasons]

            preds = []
            for i in range(min(3, len(tids))):
                try:
                    prob = float(tprobs[i]) if i < len(tprobs) else 0.0
                except (ValueError, IndexError):
                    prob = 0.0
                preds.append({
                    "technique_id": tids[i] if i < len(tids) else "?",
                    "technique_name": tnames[i] if i < len(tnames) else "?",
                    "tactic": ttactics[i] if i < len(ttactics) else "?",
                    "probability": prob,
                    "confidence_tier": tconfs[i] if i < len(tconfs) else "low",
                    "reasoning": treasons[i] if i < len(treasons) else ""
                })
            return tactic_name, preds
    except Exception:
        return "Unknown", []

async def safe_send(ws, msg):
    try:
        await ws.send_json(msg)
    except Exception:
        pass

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    last_count = await get_episode_count()
    await safe_send(websocket, {"type": "init", "count": last_count})

    while True:
        try:
            await asyncio.sleep(2)
            new_count = await get_episode_count()

            if new_count > last_count:
                last_count = new_count

                # Get the latest episode info
                latest = await get_latest_episode()
                sig = {
                    "host": (latest.get("host", "unknown") if latest else "unknown"),
                    "source_ip": "10.0.0.5",
                    "event_type": (latest.get("signal_type", "unknown") if latest else "unknown"),
                    "severity": "high",
                    "raw_event": (latest.get("signal_type", "") if latest else "")
                }

                # Animate pipeline
                await safe_send(websocket, {"type": "signal", "data": sig})
                await asyncio.sleep(0.3)
                await safe_send(websocket, {"type": "node", "node": "ingest", "state": "active"})
                await asyncio.sleep(0.5)
                await safe_send(websocket, {"type": "node", "node": "ingest", "state": "done"})
                await safe_send(websocket, {"type": "node", "node": "splunk", "state": "active"})
                await asyncio.sleep(0.7)
                await safe_send(websocket, {"type": "node", "node": "splunk", "state": "done"})
                await safe_send(websocket, {"type": "node", "node": "classify", "state": "active"})
                await asyncio.sleep(0.5)

                # Wait for the agent to finish, then get predictions from Splunk
                tactic_name, preds = "Unknown", []
                for _ in range(30):
                    await asyncio.sleep(2)
                    tactic_name, preds = await get_splunk_predictions()
                    if preds:
                        break

                await safe_send(websocket, {"type": "node", "node": "classify", "state": "done", "result": tactic_name})
                await asyncio.sleep(0.5)
                await safe_send(websocket, {"type": "node", "node": "gametree", "state": "active"})
                await asyncio.sleep(0.8)
                await safe_send(websocket, {"type": "node", "node": "gametree", "state": "done", "result": str(len(preds)) + " moves"})
                await asyncio.sleep(0.5)
                await safe_send(websocket, {"type": "node", "node": "llm", "state": "active"})
                await asyncio.sleep(1.0)
                await safe_send(websocket, {"type": "node", "node": "llm", "state": "done"})
                await asyncio.sleep(0.5)
                await safe_send(websocket, {"type": "node", "node": "brief", "state": "active"})
                await asyncio.sleep(0.8)
                await safe_send(websocket, {"type": "node", "node": "brief", "state": "done"})
                await safe_send(websocket, {"type": "predictions", "data": preds})
                await safe_send(websocket, {"type": "done"})

        except WebSocketDisconnect:
            break
        except Exception:
            pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
