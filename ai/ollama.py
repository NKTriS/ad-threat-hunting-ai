from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class OllamaError(RuntimeError):
    pass


ANALYSIS_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "analysis.schema.json"


def _analysis_schema() -> dict[str, Any]:
    payload = json.loads(ANALYSIS_SCHEMA_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise OllamaError("Analysis schema must be a JSON object")
    return payload


class OllamaClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        embedding_model: str = "nomic-embed-text",
        chat_model: str = "qwen3:4b",
        timeout_seconds: int = 600,
        context_tokens: int = 4096,
        max_output_tokens: int = 768,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.embedding_model = embedding_model
        self.chat_model = chat_model
        self.timeout_seconds = timeout_seconds
        self.context_tokens = context_tokens
        self.max_output_tokens = max_output_tokens

    def _post(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}{endpoint}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout_seconds
            ) as response:
                body = response.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise OllamaError(
                f"Cannot reach Ollama at {self.base_url}. Is it running? {exc}"
            ) from exc
        try:
            result = json.loads(body)
        except json.JSONDecodeError as exc:
            raise OllamaError("Ollama returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise OllamaError("Ollama returned an unexpected response")
        if result.get("error"):
            raise OllamaError(str(result["error"]))
        return result

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        result = self._post(
            "/api/embed",
            {
                "model": self.embedding_model,
                "input": texts,
                "keep_alive": 0,
            },
        )
        embeddings = result.get("embeddings")
        if not isinstance(embeddings, list):
            raise OllamaError("Ollama embedding response has no embeddings array")
        return [[float(value) for value in vector] for vector in embeddings]

    def chat_json(self, messages: list[dict[str, str]]) -> str:
        result = self._post(
            "/api/chat",
            {
                "model": self.chat_model,
                "messages": messages,
                "stream": False,
                "format": _analysis_schema(),
                "think": False,
                "keep_alive": 0,
                "options": {
                    "num_ctx": self.context_tokens,
                    "num_predict": self.max_output_tokens,
                    "temperature": 0.1,
                },
            },
        )
        message = result.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise OllamaError("Ollama chat response has no message content")
        return message["content"]
