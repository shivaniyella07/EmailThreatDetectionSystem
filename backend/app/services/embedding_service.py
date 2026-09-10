"""Lazy-load semantic embedding model for local NLP analysis."""

from __future__ import annotations

from typing import Any

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
_model: Any | None = None


def get_embedding_model() -> Any | None:
    """Return the lazily loaded SentenceTransformer model or None on failure."""
    global _model

    if _model is not None:
        return _model

    try:
        from sentence_transformers import SentenceTransformer
    except Exception as exc:  # pragma: no cover - exercised at runtime
        print(f"Embedding model import failed: {exc}")
        return None

    try:
        _model = SentenceTransformer(MODEL_NAME, device="cpu")
        return _model
    except Exception as exc:  # pragma: no cover - exercised at runtime
        print(f"Embedding model load failed: {exc}")
        _model = None
        return None


def generate_embedding(text: str | None) -> dict[str, Any]:
    """Generate a normalized embedding for a text input.

    Returns a controlled result dictionary so the NLP analyzer can gracefully
    degrade when the model or dependency is unavailable.
    """
    if text is None or not str(text).strip():
        return {"ok": False, "embedding": None, "error": "No analyzable text was provided."}

    model = get_embedding_model()
    if model is None:
        return {
            "ok": False,
            "embedding": None,
            "error": "Sentence-transformers embedding model is unavailable.",
        }

    try:
        vector = model.encode(
            str(text),
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        embedding = [float(value) for value in vector.tolist()]
        return {"ok": True, "embedding": embedding, "error": None}
    except Exception as exc:  # pragma: no cover - exercised at runtime
        return {
            "ok": False,
            "embedding": None,
            "error": f"Embedding generation failed: {exc}",
        }
