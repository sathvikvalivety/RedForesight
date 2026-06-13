import json
from datetime import datetime
from typing import List

from memory.vector_store import VectorStore
from agent.schemas import IncidentEpisode, ObservedSignal
from memory.semantic import embed_text

class EpisodicMemory:
    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store

    def _build_embedding_text(self, signal: ObservedSignal) -> str:
        return f"{signal.raw_event} {signal.event_type} {signal.host}"

    def store_episode(self, episode: IncidentEpisode) -> str:
        episode_json = episode.model_dump_json()
        embedding_text = self._build_embedding_text(episode.signal)
        embedding = embed_text(embedding_text)
        
        episode_id_str = str(episode.episode_id)
        metadata = {
            "signal_id": episode.signal.signal_id,
            "host": episode.signal.host,
            "event_type": episode.signal.event_type,
            "severity": episode.signal.severity,
            "tactic_classification": "",
            "outcome_confirmed": "pending" if episode.outcome_confirmed is None else str(episode.outcome_confirmed),
            "created_at": episode.created_at.isoformat()
        }
        
        self.vector_store.upsert(
            ids=[episode_id_str],
            embeddings=[embedding],
            documents=[episode_json],
            metadatas=[metadata]
        )
        
        return episode_id_str

    def recall_similar(self, signal: ObservedSignal, top_k: int = 3) -> List[IncidentEpisode]:
        if self.count() == 0:
            return []
            
        embedding_text = self._build_embedding_text(signal)
        embedding = embed_text(embedding_text)
        
        results = self.vector_store.query(query_embedding=embedding, n_results=top_k)
        
        episodes = []
        for result in results:
            doc = result.get("document")
            if doc:
                try:
                    episodes.append(IncidentEpisode.model_validate_json(doc))
                except Exception:
                    pass
                    
        return episodes

    def update_outcome(self, episode_id: str, confirmed_technique_id: str, outcome_confirmed: bool) -> None:
        record = self.vector_store.get(episode_id)
        if not record or not record.get("document"):
            return
            
        try:
            episode = IncidentEpisode.model_validate_json(record["document"])
            episode.confirmed_technique_id = confirmed_technique_id
            episode.outcome_confirmed = outcome_confirmed
            episode.closed_at = datetime.utcnow()
            
            # Re-upsert
            self.store_episode(episode)
        except Exception:
            pass

    def count(self) -> int:
        return self.vector_store.count()
