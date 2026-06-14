import asyncio
import logging
from uuid import uuid4
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from agent.schemas import ObservedSignal
from agent.orchestrator import run_agent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/trigger", tags=["Webhook"])

# Simple in-memory store for task statuses (for demo purposes)
TASK_STATUS: Dict[str, Dict[str, Any]] = {}

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
        
        brief = await run_agent(
            signal=signal,
            mcp_client=mcp_client,
            agent_memory=agent_memory,
            game_tree=game_tree,
            classifier=classifier,
            llm_client=llm_client
        )
        
        # Write brief to Splunk
        await alert_writer.write_brief(brief)
        
        TASK_STATUS[task_id]["status"] = "completed"
        TASK_STATUS[task_id]["brief"] = brief.model_dump(mode="json")
        
    except Exception as e:
        logger.error(f"Error running agent for task {task_id}: {e}")
        TASK_STATUS[task_id]["status"] = "failed"
        TASK_STATUS[task_id]["error"] = str(e)


@router.post("", status_code=202)
async def receive_trigger(payload: TriggerPayload, request: Request, background_tasks: BackgroundTasks):
    task_id = str(uuid4())
    signal_id = payload.signal_id or task_id
    TASK_STATUS[task_id] = {"status": "pending"}
    
    # Run the orchestrator in the background
    background_tasks.add_task(
        background_run_agent, 
        task_id, 
        payload, 
        request.app.state
    )
    
    return {"status": "accepted", "signal_id": signal_id}



@router.get("/status/{task_id}")
async def get_task_status(task_id: str):
    if task_id not in TASK_STATUS:
        raise HTTPException(status_code=404, detail="Task not found")
    return TASK_STATUS[task_id]
