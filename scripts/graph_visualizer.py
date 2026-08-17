"""
RedForesight Graph Visualizer - Live pipeline graph on port 8081
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
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict, Any

app = FastAPI(title="RedForesight Graph Visualizer")
API_BASE = "http://127.0.0.1:8080/api/v1"
API_KEY = os.getenv("API_KEY", "redforesight_demo_key_2026")
connected_clients = set()

async def broadcast(msg):
    dead = set()
    for ws in connected_clients:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.add(ws)
    connected_clients.difference_update(dead)

class TriggerBody(BaseModel):
    host: str = "CORP-DC-01"
    source_ip: str = "10.0.0.5"
    event_type: str
    raw_event: str
    severity: str = "high"
    splunk_index: str = "botsv3"
    additional_context: Dict[str, Any] = {}

HTML = open(Path(__file__).parent / "graph_viz.html", "r", encoding="utf-8").read()

@app.get("/")
async def get_page():
    return HTMLResponse(HTML)

@app.post("/trigger")
async def trigger(body: TriggerBody):
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            r = await client.post(
                API_BASE + "/trigger",
                json=body.model_dump(),
                headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
                follow_redirects=True
            )
            data = r.json()
            task_id = data.get("task_id", "")
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

        await broadcast({"type": "signal", "data": body.model_dump()})

        await asyncio.sleep(0.4)
        await broadcast({"type": "node", "node": "ingest", "state": "active"})
        await asyncio.sleep(0.5)
        await broadcast({"type": "node", "node": "ingest", "state": "done"})

        await broadcast({"type": "node", "node": "splunk", "state": "active"})
        await asyncio.sleep(0.7)
        await broadcast({"type": "node", "node": "splunk", "state": "done"})

        await broadcast({"type": "node", "node": "classify", "state": "active"})
        await asyncio.sleep(0.5)

        for attempt in range(60):
            await asyncio.sleep(2)
            try:
                sr = await client.get(
                    API_BASE + "/trigger/status/" + task_id,
                    headers={"X-API-Key": API_KEY},
                    follow_redirects=True
                )
                sd = sr.json()
                status = sd.get("status")
                if status == "completed":
                    brief = sd.get("brief", {})
                    tactic = brief.get("tactic_classification", "Unknown")
                    await broadcast({"type": "node", "node": "classify", "state": "done", "result": tactic})

                    preds = brief.get("ranked_predictions", [])
                    await asyncio.sleep(0.5)
                    await broadcast({"type": "node", "node": "gametree", "state": "active"})
                    await asyncio.sleep(0.8)
                    await broadcast({"type": "node", "node": "gametree", "state": "done", "result": str(len(preds)) + " moves"})

                    await asyncio.sleep(0.5)
                    await broadcast({"type": "node", "node": "llm", "state": "active"})
                    await asyncio.sleep(1.0)
                    await broadcast({"type": "node", "node": "llm", "state": "done"})

                    await asyncio.sleep(0.5)
                    await broadcast({"type": "node", "node": "brief", "state": "active"})
                    await asyncio.sleep(0.8)
                    await broadcast({"type": "node", "node": "brief", "state": "done"})

                    top3 = preds[:3] if preds else []
                    await broadcast({"type": "predictions", "data": top3})
                    await broadcast({"type": "done"})
                    break
                elif status == "failed":
                    await broadcast({"type": "error", "message": sd.get("error", "Agent failed")})
                    break
            except Exception:
                continue

    return {"status": "ok", "task_id": task_id}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        connected_clients.discard(websocket)


class NotifyBody(BaseModel):
    task_id: str
    signal: Dict[str, Any] = {}

@app.post("/notify")
async def notify(body: NotifyBody):
    """Receive notification from Splunk trigger page and stream to graph clients."""
    await broadcast({"type": "signal", "data": body.signal})
    await asyncio.sleep(0.3)
    await broadcast({"type": "node", "node": "ingest", "state": "active"})
    await asyncio.sleep(0.5)
    await broadcast({"type": "node", "node": "ingest", "state": "done"})
    await broadcast({"type": "node", "node": "splunk", "state": "active"})
    await asyncio.sleep(0.7)
    await broadcast({"type": "node", "node": "splunk", "state": "done"})
    await broadcast({"type": "node", "node": "classify", "state": "active"})

    # Poll the main API for the task result
    async with httpx.AsyncClient(timeout=120.0) as client:
        for attempt in range(60):
            await asyncio.sleep(2)
            try:
                sr = await client.get(
                    API_BASE + "/trigger/status/" + body.task_id,
                    headers={"X-API-Key": API_KEY},
                    follow_redirects=True
                )
                sd = sr.json()
                status = sd.get("status")
                if status == "completed":
                    brief = sd.get("brief", {})
                    tactic = brief.get("tactic_classification", "Unknown")
                    await broadcast({"type": "node", "node": "classify", "state": "done", "result": tactic})
                    preds = brief.get("ranked_predictions", [])
                    await asyncio.sleep(0.5)
                    await broadcast({"type": "node", "node": "gametree", "state": "active"})
                    await asyncio.sleep(0.8)
                    await broadcast({"type": "node", "node": "gametree", "state": "done", "result": str(len(preds)) + " moves"})
                    await asyncio.sleep(0.5)
                    await broadcast({"type": "node", "node": "llm", "state": "active"})
                    await asyncio.sleep(1.0)
                    await broadcast({"type": "node", "node": "llm", "state": "done"})
                    await asyncio.sleep(0.5)
                    await broadcast({"type": "node", "node": "brief", "state": "active"})
                    await asyncio.sleep(0.8)
                    await broadcast({"type": "node", "node": "brief", "state": "done"})
                    await broadcast({"type": "predictions", "data": preds[:3]})
                    await broadcast({"type": "done"})
                    break
                elif status == "failed":
                    await broadcast({"type": "error", "message": sd.get("error", "Agent failed")})
                    break
            except Exception:
                continue
    return {"status": "ok"}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
