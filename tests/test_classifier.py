import pytest
from agent.classifier import TacticClassifier
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

@pytest.fixture
def signal_unknown():
    return ObservedSignal(
        signal_id="test_id_2",
        timestamp="2026-06-16T10:00:00Z",
        host="TEST-HOST",
        source_ip="192.168.1.100",
        raw_event="hello world this is not a security event",
        event_type="unknown",
        severity="low",
        splunk_index="botsv3",
        additional_context={}
    )

@pytest.mark.asyncio
async def test_classify_credential_access(agent_memory, signal_lsass):
    classifier = TacticClassifier(agent_memory)
    tactic, tactic_id, confidence = await classifier.classify(signal_lsass)
    assert tactic == "Credential Access"
    assert tactic_id == "TA0006"
    assert 0.0 <= confidence <= 1.0

@pytest.mark.asyncio
async def test_classify_returns_tuple_of_three(agent_memory, signal_lsass):
    classifier = TacticClassifier(agent_memory)
    result = await classifier.classify(signal_lsass)
    assert isinstance(result, tuple)
    assert len(result) == 3
    assert all(item is not None for item in result)
    assert result[1].startswith("TA")

@pytest.mark.asyncio
async def test_classify_unknown_signal(agent_memory, signal_unknown):
    classifier = TacticClassifier(agent_memory)
    # Assert the function returns without raising
    result = await classifier.classify(signal_unknown)
    assert len(result) == 3
