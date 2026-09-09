from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai.analyzer import analyze_incident
from ai.rag.index import build_index
from ai.rag.retriever import LocalRetriever
from correlation import NormalizedEvent, correlate_events, load_wazuh_alerts


ROOT = Path(__file__).resolve().parents[1]


class KeywordEmbedder:
    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            lowered = text.casefold()
            vectors.append(
                [
                    float("password" in lowered or "4625" in lowered),
                    float("kerberoast" in lowered or "kerberos" in lowered or "4769" in lowered),
                    float("discovery" in lowered or "4688" in lowered),
                    1.0,
                ]
            )
        return vectors


class FakeChatModel:
    def chat_json(self, messages: list[dict[str, str]]) -> str:
        request = json.loads(messages[-1]["content"])
        incident = request["incident"]
        source = request["retrieved_references"][0]
        return json.dumps(
            {
                "incident_id": incident["incident_id"],
                "technique": incident["technique"],
                "mitre_id": incident["mitre_id"],
                "classification": "needs_review",
                "risk": incident["severity"],
                "confidence": 0.8,
                "evidence": [incident["correlation_reason"]],
                "explanation_vi": "Can xac minh them bang chung.",
                "recommendations_vi": ["Kiem tra tai khoan va may nguon."],
                "sources": [
                    {"title": source["title"], "url": source["source_url"]},
                    {"title": "invalid", "url": "https://invalid.example/"},
                ],
                "limitations_vi": ["Day la du lieu mau."],
            }
        )


class PipelineTests(unittest.TestCase):
    def test_wazuh_normalization_and_correlation(self) -> None:
        events = load_wazuh_alerts(ROOT / "data" / "sample_alerts.jsonl")
        self.assertEqual(len(events), 7)
        self.assertEqual(events[0].event_id, "4625")
        self.assertEqual(events[0].source_ip, "10.10.10.30")

        incidents = correlate_events(events)
        self.assertEqual(len(incidents), 3)
        self.assertEqual(
            {incident.mitre_id for incident in incidents},
            {"T1110.003", "T1558.003", "T1087.002"},
        )

    def test_password_spray_uses_sliding_window(self) -> None:
        base = datetime(2026, 8, 27, 3, 4, 50, tzinfo=timezone.utc)
        events = []
        for index, username in enumerate(("a", "b", "c", "d", "e")):
            events.append(
                NormalizedEvent(
                    event_uid=f"boundary-{index}",
                    timestamp=base + timedelta(seconds=index * 10),
                    host="DC01",
                    agent_id="001",
                    source_ip="10.10.10.30",
                    username=username,
                    event_id="4625",
                    channel="Security",
                    provider="Microsoft-Windows-Security-Auditing",
                    rule_id="60122",
                    rule_level=5,
                    rule_description="Logon failure",
                )
            )
        incidents = correlate_events(events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].mitre_id, "T1110.003")

    def test_rag_index_retrieval_and_analysis(self) -> None:
        embedder = KeywordEmbedder()
        events = load_wazuh_alerts(ROOT / "data" / "sample_alerts.jsonl")
        incident = next(
            item for item in correlate_events(events) if item.mitre_id == "T1558.003"
        )

        with tempfile.TemporaryDirectory() as directory:
            index_path = Path(directory) / "index.json"
            result = build_index(
                ROOT / "data" / "knowledge" / "knowledge_base.json",
                index_path,
                embedder,
                embedding_model="test-keywords",
            )
            self.assertGreaterEqual(result["document_count"], 8)

            retriever = LocalRetriever(index_path, embedder)
            matches = retriever.search("Kerberoasting Event 4769", top_k=2)
            self.assertTrue(any("Kerberoast" in match.title for match in matches))

            report = analyze_incident(
                incident, retriever, FakeChatModel(), top_k=2
            )
            self.assertEqual(report["mitre_id"], "T1558.003")
            self.assertEqual(len(report["sources"]), 1)
            self.assertIn("retrieved_chunks", report["rag_context"])


if __name__ == "__main__":
    unittest.main()
