import pytest
import chromadb
from unittest.mock import patch
from agent.memory import AgentMemory

@pytest.fixture
def agent_memory(mock_embedding_model):
    with patch("memory.vector_store.chromadb.HttpClient") as mock_client:
        mock_client.return_value = chromadb.EphemeralClient()
        memory = AgentMemory()
        
        # Seed semantic store with T1003 OS Credential Dumping
        doc = "Technique: T1003 OS Credential Dumping\nTactic: Credential Access\nDescription: Adversaries may attempt to access credentials and credential material from the operating system\nDetection: Monitor for lsass.exe\nPlatforms: Windows"
        metadata = {
            "technique_id": "T1003",
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "platforms": "Windows"
        }
        
        # We need to run this synchronously for the test setup
        memory.semantic_store.upsert(
            ids=["T1003"],
            embeddings=[mock_embedding_model.return_value],
            documents=[doc],
            metadatas=[metadata]
        )
        
        yield memory

@pytest.fixture
def mock_embedding_model():
    with patch("memory.semantic.embed_text") as mock_embed:
        # Return a dummy vector of 384 dimensions (default sentence-transformers size)
        mock_embed.return_value = [0.1] * 384
        yield mock_embed
