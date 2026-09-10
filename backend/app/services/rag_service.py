"""Local RAG retrieval for phishing and social-engineering knowledge."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.embedding_service import generate_embedding

KNOWLEDGE_PATH = Path(__file__).resolve().parents[1] / "data" / "threat_knowledge"
CHROMA_PATH = Path(__file__).resolve().parents[1] / "data" / ".chromadb"
_COLLECTION_NAME = "threat_knowledge"

_collection: Any | None = None


def _load_knowledge_entries() -> list[dict[str, Any]]:
    """Load all threat knowledge entries from the local JSON knowledge base."""
    if not KNOWLEDGE_PATH.exists():
        return []

    entries: list[dict[str, Any]] = []
    for json_path in sorted(KNOWLEDGE_PATH.glob("*.json")):
        try:
            import json

            with json_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            continue

        if isinstance(data, dict):
            items = data.get("entries", [])
        elif isinstance(data, list):
            items = data
        else:
            items = []

        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    entries.append(item)
    return entries


def _document_text(entry: dict[str, Any]) -> str:
    techniques = " ".join(entry.get("techniques", []) or [])
    patterns = " ".join(entry.get("example_patterns", []) or [])
    return " ".join(
        [
            str(entry.get("attack_type", "")),
            str(entry.get("description", "")),
            techniques,
            patterns,
        ]
    )


def _to_metadata(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(entry.get("id", "unknown")),
        "attack_type": str(entry.get("attack_type", "unknown")),
        "description": str(entry.get("description", "")),
        "techniques": ", ".join(entry.get("techniques", []) or []),
        "example_patterns": ", ".join(entry.get("example_patterns", []) or []),
        "risk_level": str(entry.get("risk_level", "unknown")),
    }


def _initialize_collection() -> Any | None:
    """Create or reuse the local Chroma collection with lazy initialization."""
    global _collection

    if _collection is not None:
        return _collection

    try:
        import chromadb
    except Exception:
        return None

    try:
        client = chromadb.PersistentClient(path=str(CHROMA_PATH))
        collection = client.get_or_create_collection(
            name=_COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
    except Exception:
        return None

    entries = _load_knowledge_entries()
    if not entries:
        _collection = collection
        return collection

    try:
        existing = collection.count()
        if existing == 0:
            ids: list[str] = []
            texts: list[str] = []
            metadata: list[dict[str, Any]] = []
            embeddings: list[list[float]] = []

            for entry in entries:
                text = _document_text(entry)
                if not text.strip():
                    continue
                embedding_result = generate_embedding(text)
                if not embedding_result.get("ok"):
                    continue
                vector = embedding_result.get("embedding")
                if not vector:
                    continue

                ids.append(str(entry.get("id", "unknown")))
                texts.append(text)
                metadata.append(_to_metadata(entry))
                embeddings.append(vector)

            if embeddings:
                collection.add(
                    ids=ids,
                    embeddings=embeddings,
                    metadatas=metadata,
                    documents=texts,
                )
    except Exception:
        return None

    _collection = collection
    return collection


def search_knowledge(query: str, limit: int = 5, min_similarity: float = 0.28) -> list[dict[str, Any]]:
    """Search the local knowledge base for semantically similar threat patterns."""
    if not query or not str(query).strip():
        return []

    collection = _initialize_collection()
    if collection is None:
        return []

    embedding_result = generate_embedding(query)
    if not embedding_result.get("ok") or not embedding_result.get("embedding"):
        return []

    try:
        results = collection.query(
            query_embeddings=[embedding_result["embedding"]],
            n_results=max(1, limit),
            include=["distances", "metadatas", "documents"],
        )
    except Exception:
        return []

    matches: list[dict[str, Any]] = []
    if not results or not results.get("ids"):
        return matches

    ids = results.get("ids", [[]])[0]
    distances = results.get("distances", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    documents = results.get("documents", [[]])[0]

    for idx, document_id in enumerate(ids):
        distance = distances[idx] if idx < len(distances) else 1.0
        metadata = metadatas[idx] if idx < len(metadatas) else {}
        document = documents[idx] if idx < len(documents) else ""
        similarity = max(0.0, min(1.0, 1.0 - float(distance)))

        if similarity < min_similarity:
            continue

        matches.append(
            {
                "id": str(document_id),
                "attack_type": str(metadata.get("attack_type", "unknown")),
                "similarity": round(float(similarity), 4),
                "description": str(metadata.get("description", document)),
                "techniques": str(metadata.get("techniques", "")).split(", ") if str(metadata.get("techniques", "")).strip() else [],
                "example_patterns": str(metadata.get("example_patterns", "")).split(", ") if str(metadata.get("example_patterns", "")).strip() else [],
                "risk_level": str(metadata.get("risk_level", "unknown")),
            }
        )

    return matches
