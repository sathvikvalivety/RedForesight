import chromadb
from typing import List, Dict, Any, Optional

class VectorStore:
    def __init__(self, host: str, port: int, collection_name: str):
        self.host = host
        self.port = port
        self.collection_name = collection_name
        self.client = chromadb.HttpClient(host=host, port=port)
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"}
        )

    def upsert(self, ids: List[str], embeddings: List[List[float]], documents: List[str], metadatas: List[Dict[str, Any]]) -> None:
        self.collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas
        )

    def query(self, query_embedding: List[float], n_results: int = 5, where: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        kwargs = {
            "query_embeddings": [query_embedding],
            "n_results": n_results,
            "include": ["documents", "metadatas", "distances"]
        }
        if where:
            kwargs["where"] = where
            
        result = self.collection.query(**kwargs)
        
        flat_results = []
        if not result["ids"] or not result["ids"][0]:
            return flat_results
            
        for i in range(len(result["ids"][0])):
            flat_results.append({
                "id": result["ids"][0][i],
                "document": result["documents"][0][i],
                "metadata": result["metadatas"][0][i],
                "distance": result["distances"][0][i] if "distances" in result and result["distances"] else None
            })
            
        return flat_results

    def get(self, id: str) -> Optional[Dict[str, Any]]:
        result = self.collection.get(
            ids=[id],
            include=["documents", "metadatas", "embeddings"]
        )
        if not result["ids"]:
            return None
            
        return {
            "id": result["ids"][0],
            "document": result["documents"][0],
            "metadata": result["metadatas"][0],
            "embedding": result["embeddings"][0] if "embeddings" in result and result["embeddings"] else None
        }

    def delete(self, id: str) -> None:
        self.collection.delete(ids=[id])

    def count(self) -> int:
        return self.collection.count()

    def reset(self) -> None:
        try:
            self.client.delete_collection(self.collection_name)
        except Exception:
            pass
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )
