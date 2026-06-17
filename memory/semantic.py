from typing import List, Dict, Optional, Any
from sentence_transformers import SentenceTransformer
from agent.schemas import MitreTechnique
from memory.vector_store import VectorStore

_model = None

def load_embedding_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _model

def embed_text(text: str) -> List[float]:
    model = load_embedding_model()
    # encode returns a numpy array, convert to list of floats
    return model.encode([text])[0].tolist()

def embed_batch(texts: List[str]) -> List[List[float]]:
    model = load_embedding_model()
    return model.encode(texts).tolist()

def build_technique_document(technique: MitreTechnique) -> str:
    description = technique.description[:500] if technique.description else ""
    detection = technique.detection[:300] if technique.detection else ""
    platforms_str = ", ".join(technique.platforms) if technique.platforms else ""
    
    doc = f"Technique: {technique.technique_id} {technique.name}\n"
    doc += f"Tactic: {technique.tactic}\n"
    doc += f"Description: {description}\n"
    doc += f"Detection: {detection}\n"
    doc += f"Platforms: {platforms_str}"
    
    return doc

def seed_collection(techniques: List[MitreTechnique], vector_store: VectorStore) -> int:
    batch_size = 50
    total_embedded = 0
    
    for i in range(0, len(techniques), batch_size):
        batch = techniques[i:i + batch_size]
        print(f"Embedding batch {i // batch_size + 1}/{(len(techniques) + batch_size - 1) // batch_size}...")
        
        ids = [t.technique_id for t in batch]
        documents = [build_technique_document(t) for t in batch]
        embeddings = embed_batch(documents)
        metadatas = [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "tactic_id": t.tactic_id,
                "platforms": ", ".join(t.platforms) if t.platforms else ""
            }
            for t in batch
        ]
        
        vector_store.upsert(ids=ids, embeddings=embeddings, documents=documents, metadatas=metadatas)
        total_embedded += len(batch)
        
    return total_embedded

def search_techniques(query_text: str, vector_store: VectorStore, top_k: int = 5, tactic_filter: Optional[str] = None) -> List[MitreTechnique]:
    embedding = embed_text(query_text)
    
    where = None
    if tactic_filter:
        where = {"tactic": tactic_filter}
        
    results = vector_store.query(query_embedding=embedding, n_results=top_k, where=where)
    
    techniques = []
    for res in results:
        m = res["metadata"]
        
        # Parse platforms
        platforms = [p.strip() for p in m.get("platforms", "").split(",") if p.strip()]
        
        # The document was formatted like:
        # Technique: TXXXX Name
        # Tactic: TacticName
        # Description: desc
        # Detection: det
        # Platforms: plat
        
        doc = res.get("document", "")
        desc = ""
        det = ""
        
        # Simple extraction based on the known prefix pattern
        for line in doc.split("\n"):
            if line.startswith("Description: "):
                desc = line[13:]
            elif line.startswith("Detection: "):
                det = line[11:]
        
        tech = MitreTechnique(
            technique_id=m.get("technique_id", ""),
            name=m.get("name", ""),
            tactic=m.get("tactic", ""),
            tactic_id=m.get("tactic_id", ""),
            description=desc if desc else doc,
            detection=det,
            platforms=platforms,
            procedure_examples=[],
            sub_techniques=[]
        )
        
        techniques.append(tech)
        
    return techniques
