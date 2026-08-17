import asyncio
import logging
from uuid import uuid4
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from agent.schemas import ObservedSignal
from agent.orchestrator import run_agent

from cachetools import TTLCache

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/trigger", tags=["Webhook"])

# TTL Cache for task statuses (keeps tasks for 1 hour to prevent memory leaks)
TASK_STATUS: TTLCache = TTLCache(maxsize=10000, ttl=3600)

class TriggerPayload(BaseModel):
    signal_id: Optional[str] = None
    host: str
    event_type: str
    raw_event: str
    severity: str = "medium"
    source_ip: Optional[str] = None
    splunk_index: Optional[str] = "main"
    additional_context: Optional[Dict[str, Any]] = None

async def background_run_agent(task_id: str, payload: TriggerPayload, app_state: dict):
    try:
        TASK_STATUS[task_id]["status"] = "running"
        TASK_STATUS[task_id]["current_step"] = 1
        TASK_STATUS[task_id]["step_name"] = "Ingesting Signal"
        
        signal = ObservedSignal(
            signal_id=payload.signal_id or task_id,
            timestamp=str(datetime.now(timezone.utc)),
            host=payload.host,
            event_type=payload.event_type,
            raw_event=payload.raw_event,
            severity=payload.severity,
            source_ip=payload.source_ip or "",
            splunk_index=payload.splunk_index,
            additional_context=payload.additional_context or {}
        )
        
        mcp_client = app_state.mcp_client
        agent_memory = app_state.agent_memory
        game_tree = app_state.game_tree
        classifier = app_state.classifier
        llm_client = app_state.llm_client
        alert_writer = app_state.alert_writer

        def progress_callback(step: int, step_name: str, log_msg: str):
            if task_id in TASK_STATUS:
                TASK_STATUS[task_id]["current_step"] = step
                TASK_STATUS[task_id]["step_name"] = step_name
                if "logs" not in TASK_STATUS[task_id]:
                    TASK_STATUS[task_id]["logs"] = []
                TASK_STATUS[task_id]["logs"].append(log_msg)
        
        brief = await run_agent(
            signal=signal,
            mcp_client=mcp_client,
            agent_memory=agent_memory,
            game_tree=game_tree,
            classifier=classifier,
            llm_client=llm_client,
            progress_callback=progress_callback
        )
        
        # Write brief to Splunk
        await alert_writer.write_brief(brief)
        
        TASK_STATUS[task_id]["status"] = "completed"
        TASK_STATUS[task_id]["current_step"] = 6
        TASK_STATUS[task_id]["step_name"] = "Completed"
        TASK_STATUS[task_id]["brief"] = brief.model_dump(mode="json")
        
    except Exception as e:
        logger.error(f"Error running agent for task {task_id}: {e}")
        TASK_STATUS[task_id]["status"] = "failed"
        TASK_STATUS[task_id]["error"] = str(e)


import os
import httpx

async def notify_graph_visualizer(task_id: str, payload: TriggerPayload):
    graph_viz_port = os.getenv("GRAPH_VIZ_PORT", "8081")
    ports_to_try = [graph_viz_port, "8081", "8082"]
    seen = set()
    unique_ports = [p for p in ports_to_try if not (p in seen or seen.add(p))]
    
    async with httpx.AsyncClient(timeout=2.0) as client:
        for port in unique_ports:
            try:
                r = await client.post(
                    f"http://127.0.0.1:{port}/notify",
                    json={"task_id": task_id, "signal": payload.model_dump()},
                    timeout=1.5
                )
                if r.status_code == 200:
                    break
            except Exception:
                continue


@router.post("/")
async def receive_trigger(payload: TriggerPayload, request: Request, background_tasks: BackgroundTasks):
    task_id = str(uuid4())
    signal_id = payload.signal_id or task_id
    TASK_STATUS[task_id] = {
        "status": "pending",
        "current_step": 0,
        "step_name": "Pending",
        "logs": [f"[SYSTEM] Signal received from {payload.host} ({payload.event_type}). Starting agent pipeline..."]
    }
    
    # Run the orchestrator in the background
    background_tasks.add_task(
        background_run_agent, 
        task_id, 
        payload, 
        request.app.state
    )
    
    # Notify graph visualizer server if running
    background_tasks.add_task(
        notify_graph_visualizer,
        task_id,
        payload
    )
    
    return {"status": "accepted", "signal_id": signal_id, "task_id": task_id}




@router.get("/status/{task_id}")
async def get_task_status(task_id: str):
    if task_id not in TASK_STATUS:
        raise HTTPException(status_code=404, detail="Task not found")
    return TASK_STATUS[task_id]

