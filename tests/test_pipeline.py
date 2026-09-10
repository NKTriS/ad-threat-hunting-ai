from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai.analyzer import analyze_incident, is_valid_analysis_report
from ai.evaluation import compare_scores, score_reports
from ai.ollama import OllamaClient
from ai.prompts import build_analysis_messages
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
    def test_ollama_chat_disables_thinking_and_unloads_model(self) -> None:
        captured: dict[str, object] = {}
        client = OllamaClient()

        def fake_post(endpoint: str, payload: dict[str, object]) -> dict[str, object]:
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"message": {"content": "{}"}}

        client._post = fake_post  # type: ignore[method-assign]
        self.assertEqual(client.chat_json([]), "{}")
        self.assertEqual(captured["endpoint"], "/api/chat")
        payload = captured["payload"]
        self.assertIsInstance(payload, dict)
        self.assertIs(payload["think"], False)  # type: ignore[index]
        self.assertEqual(payload["keep_alive"], 0)  # type: ignore[index]
        self.assertEqual(payload["options"]["num_predict"], 768)  # type: ignore[index]
        response_schema = payload["format"]  # type: ignore[index]
        self.assertIsInstance(response_schema, dict)
        self.assertIn("classification", response_schema["required"])  # type: ignore[index]

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

            messages = build_analysis_messages(incident, matches)
            prompt_payload = json.loads(messages[-1]["content"])
            self.assertEqual(
                prompt_payload["incident"]["duration_seconds"],
                int((incident.end_time - incident.start_time).total_seconds()),
            )
            self.assertEqual(
                prompt_payload["incident"]["observed_summary"]["event_ids"],
                ["4769"],
            )
            self.assertEqual(
                prompt_payload["incident"]["observed_summary"][
                    "ticket_encryption_types"
                ],
                ["0x17"],
            )
            self.assertTrue(
                any(
                    "never recommend offensive tools" in requirement.casefold()
                    for requirement in prompt_payload["requirements"]
                )
            )

            report = analyze_incident(
                incident, retriever, FakeChatModel(), top_k=2
            )
            self.assertEqual(report["mitre_id"], "T1558.003")
            self.assertEqual(len(report["sources"]), 1)
            self.assertIn("retrieved_chunks", report["rag_context"])

    def test_evaluation_compares_rag_and_baseline(self) -> None:
        truth = [
            {
                "incident_id": "INC-1",
                "technique": "Kerberoasting",
                "mitre_id": "T1558.003",
                "classification": "true_positive",
                "expected_document_ids": ["mitre-t1558-003"],
            }
        ]
        base_report = {
            "incident_id": "INC-1",
            "technique": "Unknown",
            "mitre_id": "unknown",
            "classification": "needs_review",
            "risk": "medium",
            "confidence": 0.4,
            "evidence": [],
            "explanation_vi": "Chua ro.",
            "recommendations_vi": [],
            "sources": [],
            "limitations_vi": [],
            "rag_context": {"retrieved_chunks": []},
        }
        rag_report = {
            **base_report,
            "technique": "Kerberoasting",
            "mitre_id": "T1558.003",
            "classification": "true_positive",
            "sources": [{"title": "MITRE", "url": "https://example.test/mitre"}],
            "rag_context": {
                "query": "Kerberoasting T1558.003 Event ID 4769",
                "retrieved_chunks": [
                    {
                        "document_id": "mitre-t1558-003",
                        "source_url": "https://example.test/mitre",
                    }
                ]
            },
        }
        baseline_score = score_reports([base_report], truth)
        rag_score = score_reports([rag_report], truth)
        delta = compare_scores(rag_score, baseline_score)
        self.assertTrue(is_valid_analysis_report(rag_report))
        self.assertEqual(rag_score["metrics"]["technique_accuracy"], 1.0)
        self.assertEqual(rag_score["metrics"]["citation_validity"], 1.0)
        self.assertEqual(rag_score["metrics"]["retrieval_recall_at_k"], 1.0)
        self.assertEqual(rag_score["metrics"]["retrieval_mrr"], 1.0)
        self.assertEqual(
            rag_score["metrics"]["identifier_grounding_pass_rate"], 1.0
        )
        self.assertEqual(delta["technique_accuracy"], 1.0)

        invalid_report = {**rag_report, "confidence": "high"}
        self.assertFalse(is_valid_analysis_report(invalid_report))
        self.assertEqual(
            score_reports([invalid_report], truth)["metrics"]["schema_validity"],
            0.0,
        )

        unsupported_identifier_report = {
            **rag_report,
            "evidence": ["Unexpected Event ID 4644 was observed."],
        }
        warning_score = score_reports([unsupported_identifier_report], truth)
        self.assertEqual(
            warning_score["metrics"]["identifier_grounding_pass_rate"], 0.0
        )
        self.assertEqual(
            warning_score["identifier_grounding_warnings"][0][
                "unsupported_event_ids"
            ],
            ["4644"],
        )


if __name__ == "__main__":
    unittest.main()
