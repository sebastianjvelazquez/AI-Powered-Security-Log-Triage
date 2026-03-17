from pathlib import Path

from app.evaluation.models import BenchmarkDataset
from app.evaluation.service import BenchmarkService


def test_benchmark_service_runs_single_case_dataset() -> None:
    service = BenchmarkService(
        scenario_dir=Path(__file__).resolve().parents[1] / "scenarios",
        use_live_llm=False,
    )
    dataset = BenchmarkDataset(
        dataset_id="single_case",
        name="Single Case Dataset",
        description="Focused benchmark for one scenario.",
        cases=[
            {
                "scenario_id": "password_spray",
                "expected_severity": "Medium",
                "benign_expected": False,
            }
        ],
    )

    report = service.run_dataset(dataset)

    assert report.summary.total_cases == 1
    assert report.cases[0].scenario_id == "password_spray"
    assert report.summary.parser_success_rate > 0
    assert report.summary.llm_valid_schema_rate == 1.0


def test_benchmark_service_renders_markdown_report() -> None:
    service = BenchmarkService(
        scenario_dir=Path(__file__).resolve().parents[1] / "scenarios",
        use_live_llm=False,
    )
    dataset = service.load_dataset(Path(__file__).resolve().parents[1] / "evaluation" / "datasets" / "default" / "benchmark_manifest.json")
    report = service.run_dataset(
        BenchmarkDataset(
            dataset_id=dataset.dataset_id,
            name=dataset.name,
            description=dataset.description,
            cases=dataset.cases[:1],
        )
    )

    markdown = service.render_markdown(report)

    assert "# Benchmark Report" in markdown
    assert "Parser Success Rate" in markdown
    assert "password_spray" in markdown
