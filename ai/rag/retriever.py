from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .index import Embedder


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    chunk_id: str
    title: str
    source: str
    source_url: str
    text: str
    score: float
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "title": self.title,
            "source": self.source,
            "source_url": self.source_url,
            "text": self.text,
            "score": round(self.score, 6),
            "metadata": self.metadata,
        }


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise ValueError("Embedding dimensions do not match")
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return dot / (left_norm * right_norm)


class LocalRetriever:
    def __init__(self, index_path: str | Path, embedder: Embedder) -> None:
        payload = json.loads(Path(index_path).read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            raise ValueError("Unsupported RAG index schema")
        self.embedding_model = str(payload["embedding_model"])
        self.dimension = int(payload["dimension"])
        self.chunks = list(payload["chunks"])
        self.embedder = embedder

    def search(self, query: str, top_k: int = 4) -> list[RetrievedChunk]:
        if not query.strip():
            raise ValueError("Retrieval query cannot be empty")
        if top_k <= 0:
            raise ValueError("top_k must be positive")

        vectors = self.embedder.embed([query])
        if len(vectors) != 1 or len(vectors[0]) != self.dimension:
            raise ValueError("Query embedding does not match the stored index")
        query_vector = vectors[0]

        ranked = sorted(
            (
                (_cosine_similarity(query_vector, chunk["embedding"]), chunk)
                for chunk in self.chunks
            ),
            key=lambda item: item[0],
            reverse=True,
        )[:top_k]

        return [
            RetrievedChunk(
                chunk_id=str(chunk["chunk_id"]),
                title=str(chunk["title"]),
                source=str(chunk["source"]),
                source_url=str(chunk["source_url"]),
                text=str(chunk["text"]),
                score=float(score),
                metadata=dict(chunk.get("metadata", {})),
            )
            for score, chunk in ranked
        ]
