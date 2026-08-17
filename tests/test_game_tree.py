import pytest
from agent.game_tree import GameTree
from agent.memory import AgentMemory
from agent.schemas import ObservedSignal, SplunkContext, PredictedMove
import chromadb
from unittest.mock import patch


@pytest.fixture
def agent_memory():
    with patch("memory.vector_store.chromadb.HttpClient") as mock_client:
        mock_client.return_value = chromadb.EphemeralClient()
        am = AgentMemory()
        # Seed semantic store so game_tree.expand finds candidates
        doc = ("Technique: T1021.002 SMB Admin Shares\n"
               "Tactic: Lateral Movement\n"
               "Description: Adversaries may use valid credentials to interact with remote shares\n"
               "Detection: Monitor for admin share access\n"
               "Platforms: Windows")
        metadata = {"technique_id": "T1021.002", "name": "SMB Admin Shares",
                    "tactic": "Lateral Movement", "tactic_id": "TA0008", "platforms": "Windows"}
        am.semantic_store.upsert(ids=["T1021.002"], embeddings=[[0.1] * 384],
                                 documents=[doc], metadatas=[metadata])
        return am


@pytest.fixture
def game_tree(agent_memory):
    return GameTree(agent_memory, agent_memory.semantic_store)


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
def splunk_context():
    return SplunkContext(
        host="TEST-HOST",
        query_window_minutes=30,
        process_events=[],
        auth_events=[],
        network_events=[],
        host_summary=[],
        raw_results={}
    )


@pytest.mark.asyncio
async def test_expand_returns_predicted_moves(game_tree, signal_lsass, splunk_context):
    moves = await game_tree.expand(signal_lsass, "Credential Access", splunk_context)
    assert isinstance(moves, list)
    assert 1 <= len(moves) <= 5
    assert all(isinstance(move, PredictedMove) for move in moves)


@pytest.mark.asyncio
async def test_expand_probabilities_are_valid(game_tree, signal_lsass, splunk_context):
    moves = await game_tree.expand(signal_lsass, "Credential Access", splunk_context)
    probabilities = [move.probability for move in moves]
    assert all(0.0 <= p <= 1.0 for p in probabilities)
    assert all(p > 0.0 for p in probabilities)
    assert 0.5 <= sum(probabilities) <= 1.5


@pytest.mark.asyncio
async def test_expand_subsequent_tactics_only(game_tree, signal_lsass, splunk_context):
    moves = await game_tree.expand(signal_lsass, "Credential Access", splunk_context)
    tactics = [move.tactic for move in moves]
    assert "Credential Access" not in tactics


@pytest.mark.asyncio
async def test_expand_unknown_tactic_fallback(game_tree, signal_lsass, splunk_context):
    # Should not raise exception
    moves = await game_tree.expand(signal_lsass, "Unknown", splunk_context)
    assert isinstance(moves, list)
