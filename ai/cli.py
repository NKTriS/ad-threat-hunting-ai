from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from correlation import CorrelationConfig, Incident, correlate_events, load_wazuh_alerts
from correlation.wazuh import dump_incidents

from .analyzer import analyze_incident
from .evaluation import compare_scores, score_reports
from .ollama import OllamaClient
from .rag import LocalRetriever, build_index


DEFAULT_KNOWLEDGE = Path("data/knowledge/knowledge_base.json")
DEFAULT_INDEX = Path("data/rag_index/index.json")


def _client(args: argparse.Namespace) -> OllamaClient:
    return OllamaClient(
        base_url=args.ollama_url,
        embedding_model=args.embedding_model,
        chat_model=getattr(args, "chat_model", "qwen3:4b"),
        timeout_seconds=getattr(args, "timeout_seconds", 600),
        context_tokens=getattr(args, "context_tokens", 4096),
        max_output_tokens=getattr(args, "max_output_tokens", 768),
    )


def command_correlate(args: argparse.Namespace) -> None:
    events = load_wazuh_alerts(args.alerts)
    config = CorrelationConfig(
        window_seconds=args.window_seconds,
        password_spray_min_events=args.spray_min_events,
        password_spray_min_users=args.spray_min_users,
    )
    incidents = correlate_events(events, config)
    dump_incidents(incidents, args.output)
    print(f"Normalized {len(events)} events and wrote {len(incidents)} incidents")


def command_build_index(args: argparse.Namespace) -> None:
    client = _client(args)
    result = build_index(
        args.knowledge,
        args.output,
        client,
        embedding_model=args.embedding_model,
        chunk_words=args.chunk_words,
        overlap_words=args.overlap_words,
    )
    print(
        f"Built index with {result['document_count']} documents and "
        f"{result['chunk_count']} chunks"
    )


def command_analyze(args: argparse.Namespace) -> None:
    payload = json.loads(Path(args.incidents).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Incidents file must be a JSON array")
    incidents = [Incident.from_dict(item) for item in payload]

    client = _client(args)
    retriever = None if args.no_rag else LocalRetriever(args.index, client)
    reports = [
        analyze_incident(incident, retriever, client, top_k=args.top_k)
        for incident in incidents
    ]
    destination = Path(
        args.output
        or ("data/reports_no_rag.json" if args.no_rag else "data/reports.json")
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Analyzed {len(reports)} incidents and wrote {destination}")


def _read_json_array(path: Path, label: str) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not all(
        isinstance(item, dict) for item in payload
    ):
        raise ValueError(f"{label} must be a JSON array of objects")
    return payload


def command_evaluate(args: argparse.Namespace) -> None:
    ground_truth = _read_json_array(args.ground_truth, "Ground truth")
    rag_reports = _read_json_array(args.rag_reports, "RAG reports")
    result: dict[str, Any] = {
        "rag": score_reports(rag_reports, ground_truth),
    }
    if args.baseline_reports:
        baseline_reports = _read_json_array(
            args.baseline_reports, "Baseline reports"
        )
        result["baseline"] = score_reports(baseline_reports, ground_truth)
        result["rag_minus_baseline"] = compare_scores(
            result["rag"], result["baseline"]
        )
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Wrote evaluation metrics to {destination}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Wazuh + local RAG incident analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    correlate = subparsers.add_parser("correlate", help="Create incidents from alerts.json")
    correlate.add_argument("--alerts", required=True, type=Path)
    correlate.add_argument("--output", type=Path, default=Path("data/incidents.json"))
    correlate.add_argument("--window-seconds", type=int, default=300)
    correlate.add_argument("--spray-min-events", type=int, default=5)
    correlate.add_argument("--spray-min-users", type=int, default=5)
    correlate.set_defaults(handler=command_correlate)

    index = subparsers.add_parser("build-index", help="Embed the RAG knowledge base")
    index.add_argument("--knowledge", type=Path, default=DEFAULT_KNOWLEDGE)
    index.add_argument("--output", type=Path, default=DEFAULT_INDEX)
    index.add_argument("--embedding-model", default="nomic-embed-text")
    index.add_argument("--timeout-seconds", type=int, default=600)
    index.add_argument("--ollama-url", default=os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"))
    index.add_argument("--chunk-words", type=int, default=180)
    index.add_argument("--overlap-words", type=int, default=30)
    index.set_defaults(handler=command_build_index)

    analyze = subparsers.add_parser("analyze", help="Retrieve context and call local LLM")
    analyze.add_argument("--incidents", type=Path, default=Path("data/incidents.json"))
    analyze.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    analyze.add_argument("--output", type=Path)
    analyze.add_argument("--embedding-model", default="nomic-embed-text")
    analyze.add_argument("--chat-model", default="qwen3:4b")
    analyze.add_argument("--context-tokens", type=int, default=4096)
    analyze.add_argument("--max-output-tokens", type=int, default=768)
    analyze.add_argument("--timeout-seconds", type=int, default=600)
    analyze.add_argument("--top-k", type=int, default=4)
    analyze.add_argument(
        "--no-rag",
        action="store_true",
        help="Run a baseline analysis without retrieved references",
    )
    analyze.add_argument("--ollama-url", default=os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"))
    analyze.set_defaults(handler=command_analyze)

    evaluate = subparsers.add_parser(
        "evaluate", help="Score RAG reports and optionally compare a no-RAG baseline"
    )
    evaluate.add_argument(
        "--ground-truth",
        type=Path,
        default=Path("evaluation/ground_truth.sample.json"),
    )
    evaluate.add_argument(
        "--rag-reports", type=Path, default=Path("data/reports.json")
    )
    evaluate.add_argument("--baseline-reports", type=Path)
    evaluate.add_argument(
        "--output", type=Path, default=Path("data/evaluation.json")
    )
    evaluate.set_defaults(handler=command_evaluate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.handler(args)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
