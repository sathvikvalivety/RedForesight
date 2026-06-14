import asyncio
import os
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

from memory.vector_store import VectorStore
from memory.episodic import EpisodicMemory
from memory.semantic import search_techniques, load_embedding_model
from agent.schemas import ObservedSignal, IncidentEpisode, MitreTechnique

class AgentMemory:
    def __init__(self):
        host = os.getenv("CHROMA_HOST", "localhost")
        port = int(os.getenv("CHROMA_PORT", "8001"))
        
        mitre_collection = os.getenv("CHROMA_COLLECTION_MITRE", "mitre_techniques")
        episodes_collection = os.getenv("CHROMA_COLLECTION_EPISODES", "incident_episodes")
        
        self.semantic_store = VectorStore(host, port, mitre_collection)
        self.episodic_store = VectorStore(host, port, episodes_collection)
        self.episodic_memory = EpisodicMemory(self.episodic_store)
        
        # Load embedding model once
        load_embedding_model()
        
        # Thread pool for synchronous ChromaDB calls
        self.executor = ThreadPoolExecutor(max_workers=4)

    async def recall(self, signal: ObservedSignal, tactic_hint: Optional[str] = None) -> Dict[str, List]:
        loop = asyncio.get_running_loop()
        
        semantic_future = loop.run_in_executor(
            self.executor,
            search_techniques,
            signal.raw_event,
            self.semantic_store,
            5,
            tactic_hint
        )
        
        episodic_future = loop.run_in_executor(
            self.executor,
            self.episodic_memory.recall_similar,
            signal,
            3
        )
        
        techniques, episodes = await asyncio.gather(semantic_future, episodic_future)
        
        return {
            "techniques": techniques,
            "episodes": episodes
        }

    async def store_episode(self, episode: IncidentEpisode) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.executor,
            self.episodic_memory.store_episode,
            episode
        )

    async def update_outcome(self, episode_id: str, confirmed_technique_id: str, outcome_confirmed: bool) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.executor,
            self.episodic_memory.update_outcome,
            episode_id,
            confirmed_technique_id,
            outcome_confirmed
        )
