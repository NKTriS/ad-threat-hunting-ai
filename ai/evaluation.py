from __future__ import annotations

import json
import re
from typing import Any

from .analyzer import is_valid_analysis_report


EVENT_ID_PATTERN = re.compile(r"\bevent\s*ids?\s*[:#-]?\s*(\d{1,5})\b", re.IGNORECASE)
MITRE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _identifier_grounding_warnings(report: dict[str, Any]) -> dict[str, list[str]]:
    report_text = json.dumps(
        {
            key: report.get(key)
            for key in (
                "technique",
                "mitre_id",
                "evidence",
                "explanation_vi",
                "recommendations_vi",
                "limitations_vi",
            )
        },
        ensure_ascii=False,
    )
    rag_context = report.get("rag_context", {})
    context_text = json.dumps(rag_context, ensure_ascii=False)

    reported_event_ids = set(EVENT_ID_PATTERN.findall(report_text))
    allowed_event_ids = set(EVENT_ID_PATTERN.findall(context_text))
    reported_mitre_ids = {value.upper() for value in MITRE_ID_PATTERN.findall(report_text)}
    allowed_mitre_ids = {value.upper() for value in MITRE_ID_PATTERN.findall(context_text)}
    return {
        "unsupported_event_ids": sorted(reported_event_ids - allowed_event_ids),
        "unsupported_mitre_ids": sorted(reported_mitre_ids - allowed_mitre_ids),
    }


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def score_reports(
    reports: list[dict[str, Any]], ground_truth: list[dict[str, Any]]
) -> dict[str, Any]:
    truth_by_id = {str(item["incident_id"]): item for item in ground_truth}
    report_by_id = {
        str(item.get("incident_id")): item
        for item in reports
        if isinstance(item, dict) and item.get("incident_id")
    }
    matched_ids = sorted(set(truth_by_id) & set(report_by_id))

    valid_schema = 0
    technique_correct = 0
    mitre_correct = 0
    classification_correct = 0
    citation_valid = 0
    citation_total = 0
    reports_with_citations = 0
    retrieval_expected = 0
    retrieval_found = 0
    retrieval_cases = 0
    retrieval_hits = 0
    reciprocal_rank_total = 0.0
    reports_without_unsupported_identifiers = 0
    identifier_grounding_warnings = []

    for incident_id in matched_ids:
        report = report_by_id[incident_id]
        truth = truth_by_id[incident_id]
        if is_valid_analysis_report(report):
            valid_schema += 1
        if str(report.get("technique", "")).casefold() == str(
            truth.get("technique", "")
        ).casefold():
            technique_correct += 1
        if str(report.get("mitre_id", "")).casefold() == str(
            truth.get("mitre_id", "")
        ).casefold():
            mitre_correct += 1
        if str(report.get("classification", "")).casefold() == str(
            truth.get("classification", "")
        ).casefold():
            classification_correct += 1

        allowed_urls = {
            str(chunk.get("source_url"))
            for chunk in report.get("rag_context", {}).get("retrieved_chunks", [])
            if isinstance(chunk, dict) and chunk.get("source_url")
        }
        sources = [
            source
            for source in report.get("sources", [])
            if isinstance(source, dict) and source.get("url")
        ]
        if sources:
            reports_with_citations += 1
        for source in sources:
            citation_total += 1
            if str(source["url"]) in allowed_urls:
                citation_valid += 1

        expected_documents = {
            str(document_id) for document_id in truth.get("expected_document_ids", [])
        }
        if expected_documents:
            retrieval_cases += 1
            retrieved_documents = [
                str(chunk.get("document_id"))
                for chunk in report.get("rag_context", {}).get(
                    "retrieved_chunks", []
                )
                if isinstance(chunk, dict) and chunk.get("document_id")
            ]
            retrieval_expected += len(expected_documents)
            retrieval_found += len(expected_documents & set(retrieved_documents))
            first_rank = next(
                (
                    rank
                    for rank, document_id in enumerate(retrieved_documents, start=1)
                    if document_id in expected_documents
                ),
                None,
            )
            if first_rank is not None:
                retrieval_hits += 1
                reciprocal_rank_total += 1 / first_rank

        warnings = _identifier_grounding_warnings(report)
        if not any(warnings.values()):
            reports_without_unsupported_identifiers += 1
        else:
            identifier_grounding_warnings.append(
                {"incident_id": incident_id, **warnings}
            )

    expected_count = len(truth_by_id)
    matched_count = len(matched_ids)
    return {
        "expected_incidents": expected_count,
        "reported_incidents": len(report_by_id),
        "matched_incidents": matched_count,
        "missing_incident_ids": sorted(set(truth_by_id) - set(report_by_id)),
        "unexpected_incident_ids": sorted(set(report_by_id) - set(truth_by_id)),
        "metrics": {
            "incident_recall": _ratio(matched_count, expected_count),
            "schema_validity": _ratio(valid_schema, matched_count),
            "technique_accuracy": _ratio(technique_correct, matched_count),
            "mitre_accuracy": _ratio(mitre_correct, matched_count),
            "classification_accuracy": _ratio(
                classification_correct, matched_count
            ),
            "citation_validity": _ratio(citation_valid, citation_total),
            "citation_coverage": _ratio(reports_with_citations, matched_count),
            "retrieval_recall_at_k": _ratio(retrieval_found, retrieval_expected),
            "retrieval_hit_rate": _ratio(retrieval_hits, retrieval_cases),
            "retrieval_mrr": (
                round(reciprocal_rank_total / retrieval_cases, 4)
                if retrieval_cases
                else 0.0
            ),
            "identifier_grounding_pass_rate": _ratio(
                reports_without_unsupported_identifiers, matched_count
            ),
        },
        "identifier_grounding_warnings": identifier_grounding_warnings,
        "manual_review_required": [
            "Evidence groundedness",
            "Recommendation correctness",
            "Vietnamese explanation usefulness",
            "False claims not captured by exact-match metrics",
            "Identifier warnings may include legitimate investigation suggestions",
        ],
    }


def compare_scores(
    rag_score: dict[str, Any], baseline_score: dict[str, Any]
) -> dict[str, Any]:
    rag_metrics = rag_score["metrics"]
    baseline_metrics = baseline_score["metrics"]
    comparable = (
        "schema_validity",
        "technique_accuracy",
        "mitre_accuracy",
        "classification_accuracy",
        "identifier_grounding_pass_rate",
    )
    return {
        metric: round(rag_metrics[metric] - baseline_metrics[metric], 4)
        for metric in comparable
    }
