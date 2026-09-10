from __future__ import annotations

import json
from typing import Any, Protocol

from correlation.models import Incident

from .prompts import build_analysis_messages, build_retrieval_query
from .rag.retriever import LocalRetriever


class ChatModel(Protocol):
    def chat_json(self, messages: list[dict[str, str]]) -> str:
        ...


REQUIRED_OUTPUT_KEYS = {
    "incident_id",
    "technique",
    "mitre_id",
    "classification",
    "risk",
    "confidence",
    "evidence",
    "explanation_vi",
    "recommendations_vi",
    "sources",
    "limitations_vi",
}

VALID_CLASSIFICATIONS = {"true_positive", "false_positive", "needs_review"}
VALID_RISKS = {"low", "medium", "high", "critical"}


def is_valid_analysis_report(payload: dict[str, Any]) -> bool:
    allowed_keys = REQUIRED_OUTPUT_KEYS | {"rag_context"}
    if not REQUIRED_OUTPUT_KEYS <= payload.keys() or not payload.keys() <= allowed_keys:
        return False
    if not all(
        isinstance(payload[key], str)
        for key in ("incident_id", "technique", "mitre_id", "explanation_vi")
    ):
        return False
    if payload["classification"] not in VALID_CLASSIFICATIONS:
        return False
    if payload["risk"] not in VALID_RISKS:
        return False
    confidence = payload["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        return False
    if not 0 <= confidence <= 1:
        return False
    for key in ("evidence", "recommendations_vi", "limitations_vi"):
        value = payload[key]
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            return False
    sources = payload["sources"]
    if not isinstance(sources, list) or not all(
        isinstance(source, dict)
        and isinstance(source.get("title"), str)
        and isinstance(source.get("url"), str)
        for source in sources
    ):
        return False
    return "rag_context" not in payload or isinstance(payload["rag_context"], dict)


def _parse_model_json(content: str) -> dict[str, Any]:
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines)
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ValueError("LLM did not return valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("LLM output must be a JSON object")
    missing = REQUIRED_OUTPUT_KEYS - payload.keys()
    if missing:
        raise ValueError(f"LLM output is missing keys: {sorted(missing)}")
    normalized = {key: payload[key] for key in REQUIRED_OUTPUT_KEYS}
    if not is_valid_analysis_report(normalized):
        raise ValueError("LLM output does not match the analysis contract")
    return normalized


def analyze_incident(
    incident: Incident,
    retriever: LocalRetriever | None,
    chat_model: ChatModel,
    top_k: int = 4,
) -> dict[str, Any]:
    query = build_retrieval_query(incident)
    references = retriever.search(query, top_k=top_k) if retriever else []
    messages = build_analysis_messages(incident, references)
    result = _parse_model_json(chat_model.chat_json(messages))
    result["incident_id"] = incident.incident_id

    allowed_urls = {reference.source_url for reference in references}
    result["sources"] = [
        source
        for source in result.get("sources", [])
        if isinstance(source, dict) and source.get("url") in allowed_urls
    ]
    result["rag_context"] = {
        "enabled": retriever is not None,
        "query": query,
        "retrieved_chunks": [reference.to_dict() for reference in references],
    }
    return result
