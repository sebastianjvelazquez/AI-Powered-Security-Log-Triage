#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_BACKEND_ROOT))

from app.evaluation.service import BenchmarkService


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local benchmark scenarios against the triage pipeline.")
    parser.add_argument(
        "--dataset",
        default=str(REPO_BACKEND_ROOT / "evaluation" / "datasets" / "default" / "benchmark_manifest.json"),
        help="Path to the benchmark dataset manifest JSON.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPO_BACKEND_ROOT / "evaluation" / "reports"),
        help="Directory to write JSON and Markdown reports.",
    )
    parser.add_argument(
        "--use-live-llm",
        action="store_true",
        help="Use the configured local Ollama analyzer instead of the deterministic benchmark stub.",
    )
    args = parser.parse_args()

    service = BenchmarkService(use_live_llm=args.use_live_llm)
    dataset = service.load_dataset(args.dataset)
    report = service.run_dataset(dataset)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = report.generated_at.strftime("%Y%m%d_%H%M%S")
    json_path = output_dir / f"{dataset.dataset_id}_{timestamp}.json"
    markdown_path = output_dir / f"{dataset.dataset_id}_{timestamp}.md"

    json_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8")
    markdown_path.write_text(service.render_markdown(report), encoding="utf-8")

    print(f"Benchmark dataset: {report.dataset_name} ({report.dataset_id})")
    print(f"Parser success rate: {report.summary.parser_success_rate:.2%}")
    print(f"Detection precision: {report.summary.detection_precision:.2%}")
    print(f"Detection recall: {report.summary.detection_recall:.2%}")
    print(f"False positive rate: {report.summary.false_positive_rate:.2%}")
    print(f"Severity agreement: {report.summary.severity_agreement:.2%}")
    print(f"MITRE mapping quality: {report.summary.mitre_mapping_quality:.2%}")
    print(f"LLM valid-schema rate: {report.summary.llm_valid_schema_rate:.2%}")
    print(f"LLM fallback rate: {report.summary.llm_fallback_rate:.2%}")
    print(f"Average processing time (ms): {report.summary.average_processing_time_ms:.2f}")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
