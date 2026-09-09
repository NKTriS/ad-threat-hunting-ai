"""Small local vector index used by the RAG pipeline."""

from .index import build_index
from .retriever import LocalRetriever, RetrievedChunk

__all__ = ["LocalRetriever", "RetrievedChunk", "build_index"]
