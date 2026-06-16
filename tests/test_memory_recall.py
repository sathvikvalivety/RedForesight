import pytest
from agent.memory import AgentMemory
from agent.schemas import ObservedSignal
import chromadb
from unittest.mock import patch

@pytest.fixture
def agent_memory():
    with patch("memory.vector_store.chromadb.HttpClient") as mock_client:
        mock_client.return_value = chromadb.PersistentClient(path="db")
        return AgentMemory()

@pytest.fixture
def signal_lsass():
    return ObservedSignal(
        signal_id="test_id_1",
        timestamp="2026-06-16T10:00:00Z",
        host="TEST-HOST",
        source_ip="192.168.1.100",
        raw_event="rundll32.exe accessed lsass.exe memory for credential dumping",
        event_type="credential_access_attempt",
        severity="high",
        splunk_index="botsv3",
        additional_context={}
    )

@pytest.mark.asyncio
async def test_semantic_search_returns_techniques(agent_memory, signal_lsass):
    result = await agent_memory.recall(signal_lsass)
    techniques = result.get("techniques", [])
    assert len(techniques) > 0
    assert techniques[0].technique_id.startswith("T")

@pytest.mark.asyncio
async def test_semantic_search_credential_access_relevance(agent_memory, signal_lsass):
    result = await agent_memory.recall(signal_lsass)
    techniques = result.get("techniques", [])
    top_5_ids = [t.technique_id for t in techniques[:5]]
    # Check if T1003 or any T1003.xxx is in top 5
    assert any(tid.startswith("T1003") for tid in top_5_ids)

@pytest.mark.asyncio
async def test_episodic_recall_returns_list(agent_memory, signal_lsass):
    result = await agent_memory.recall(signal_lsass)
    episodes = result.get("episodes")
    assert isinstance(episodes, list)
