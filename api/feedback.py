import logging
from typing import Dict, Any, List
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/feedback", tags=["Feedback"])

class FeedbackPayload(BaseModel):
    episode_id: str
    confirmed_technique_id: str
    outcome_confirmed: bool

@router.post("")
async def receive_feedback(payload: FeedbackPayload, request: Request):
    try:
        agent_memory = request.app.state.agent_memory
        
        success = await agent_memory.update_outcome(
            episode_id=payload.episode_id,
            confirmed_technique_id=payload.confirmed_technique_id,
            outcome_confirmed=payload.outcome_confirmed
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Episode not found")
            
        logger.info(f"Updated episode {payload.episode_id} with outcome: {payload.outcome_confirmed}")
        return {"message": "Feedback successfully recorded."}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating feedback for episode {payload.episode_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/episodes")
async def list_episodes(request: Request):
    try:
        agent_memory = request.app.state.agent_memory
        
        # Simple hack to list recent episodes from Chroma
        # We fetch up to 20 without query filter
        results = agent_memory.episodic_store.collection.get(limit=20)
        episodes = []
        
        if results and results.get("ids"):
            for i, metadata in enumerate(results["metadatas"]):
                episodes.append({
                    "id": results["ids"][i],
                    "signal_type": metadata.get("signal_event_type", "unknown"),
                    "host": metadata.get("signal_host", "unknown"),
                    "confirmed": str(metadata.get("outcome_confirmed")).lower() == "true",
                    "confirmed_technique": metadata.get("confirmed_technique_id", None)
                })
                
        return {"episodes": episodes}
        
    except Exception as e:
        logger.error(f"Error listing episodes: {e}")
        raise HTTPException(status_code=500, detail=str(e))
