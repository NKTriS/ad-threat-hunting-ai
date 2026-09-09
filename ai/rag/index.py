from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]:
        ...


@dataclass(frozen=True, slots=True)
class KnowledgeDocument:
    document_id: str
    title: str
    source: str
    source_url: str
    content: str
    metadata: dict[str, Any]


def load_documents(path: str | Path) -> list[KnowledgeDocument]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Knowledge base must be a JSON array")

    documents: list[KnowledgeDocument] = []
    required = {"document_id", "title", "source", "source_url", "content"}
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"Knowledge item {index} must be an object")
        missing = required - item.keys()
        if missing:
            raise ValueError(f"Knowledge item {index} is missing: {sorted(missing)}")
        documents.append(
            KnowledgeDocument(
                document_id=str(item["document_id"]),
                title=str(item["title"]),
                source=str(item["source"]),
                source_url=str(item["source_url"]),
                content=str(item["content"]),
                metadata=dict(item.get("metadata", {})),
            )
        )
    return documents


def chunk_document(
    document: KnowledgeDocument, chunk_words: int = 180, overlap_words: int = 30
) -> list[dict[str, Any]]:
    if chunk_words <= 0 or overlap_words < 0 or overlap_words >= chunk_words:
        raise ValueError("Require chunk_words > overlap_words >= 0")
    words = document.content.split()
    if not words:
        return []

    chunks: list[dict[str, Any]] = []
    step = chunk_words - overlap_words
    for position, start in enumerate(range(0, len(words), step)):
        text = " ".join(words[start : start + chunk_words]).strip()
        if not text:
            continue
        raw_id = f"{document.document_id}:{position}:{text}"
        chunks.append(
            {
                "chunk_id": hashlib.sha1(raw_id.encode("utf-8")).hexdigest()[:16],
                "document_id": document.document_id,
                "title": document.title,
                "source": document.source,
                "source_url": document.source_url,
                "text": text,
                "metadata": document.metadata,
            }
        )
        if start + chunk_words >= len(words):
            break
    return chunks


def build_index(
    knowledge_path: str | Path,
    output_path: str | Path,
    embedder: Embedder,
    embedding_model: str,
    chunk_words: int = 180,
    overlap_words: int = 30,
) -> dict[str, Any]:
    documents = load_documents(knowledge_path)
    chunks = [
        chunk
        for document in documents
        for chunk in chunk_document(document, chunk_words, overlap_words)
    ]
    if not chunks:
        raise ValueError("Knowledge base produced no chunks")

    embeddings = embedder.embed([chunk["text"] for chunk in chunks])
    if len(embeddings) != len(chunks):
        raise ValueError("Embedding service returned an unexpected vector count")
    dimensions = {len(vector) for vector in embeddings}
    if len(dimensions) != 1 or 0 in dimensions:
        raise ValueError("Embedding vectors must share one non-zero dimension")

    for chunk, vector in zip(chunks, embeddings):
        chunk["embedding"] = [float(value) for value in vector]

    index_payload = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "embedding_model": embedding_model,
        "dimension": dimensions.pop(),
        "document_count": len(documents),
        "chunk_count": len(chunks),
        "chunks": chunks,
    }
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(index_payload, ensure_ascii=False), encoding="utf-8"
    )
    return index_payload
