import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from dotenv import load_dotenv

from agent.memory import AgentMemory
from agent.classifier import TacticClassifier
from agent.game_tree import GameTree
from agent.llm_client import LLMClient
from splunk.mcp_client import SplunkMCPClient
from splunk.alert_writer import AlertWriter

from api.webhook import router as webhook_router
from api.feedback import router as feedback_router

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

# Singletons
app_state = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load env
    load_dotenv()
    
    # Init singletons
    logger.info("Initializing Agent singletons...")
    
    mcp_client = SplunkMCPClient()
    agent_memory = AgentMemory()
    classifier = TacticClassifier(agent_memory)
    game_tree = GameTree(agent_memory, agent_memory.semantic_store)
    llm_client = LLMClient()
    alert_writer = AlertWriter()
    
    # Ensure MCP client connects
    try:
        is_healthy = await mcp_client.health_check()
        if is_healthy:
            logger.info("Splunk MCP connected.")
        else:
            logger.warning("Splunk MCP health check failed during startup.")
    except Exception as e:
        logger.warning(f"Splunk MCP failed to connect during startup: {e}")
        
    app.state.mcp_client = mcp_client
    app.state.agent_memory = agent_memory
    app.state.classifier = classifier
    app.state.game_tree = game_tree
    app.state.llm_client = llm_client
    app.state.alert_writer = alert_writer
    
    yield
    
    # Cleanup
    logger.info("Shutting down...")
    await mcp_client.close()
    await llm_client.close()
    await alert_writer.close()


app = FastAPI(title="RedForesight API", version="1.0.0", lifespan=lifespan)

app.include_router(webhook_router, prefix="/api/v1")
app.include_router(feedback_router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok", "agent": "ready"}
    
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("API_PORT", "8080"))
    host = os.getenv("API_HOST", "0.0.0.0")
    uvicorn.run("api.main:app", host=host, port=port, reload=True)
