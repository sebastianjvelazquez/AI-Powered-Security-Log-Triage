from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from time import perf_counter

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.evaluation.models import BenchmarkCaseResult, BenchmarkDataset, BenchmarkReport, BenchmarkSummary
from app.llm.analyzer import ResilientLLMAnalyzer
from app.models.db_models import AnalystReview, DetectionRecord, Incident, IncidentEnrichment, Upload
from app.models.schemas import IncidentBundle, LLMAnalysisOutput, LLMAnalysisResult, LLMExecutionTrace, LLMTaskTrace, ScenarioPack
from app.services.processing_pipeline_service import ProcessingPipelineService
from app.utils.mitre import map_rules_to_mitre


SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


class BenchmarkLLMAnalyzer:
    def analyze_with_fallback(self, bundle: IncidentBundle) -> LLMAnalysisResult:
        rules = [event.rule_name for event in bundle.suspicious_events]
        mitre = map_rules_to_mitre(rules) or ["T1595"]
        if bundle.detection_summary.get("port_scanning_pattern", 0) and bundle.detection_summary.get(
            "multiple_failed_logins", 0
        ):
            severity = "Critical"
            attack_type = "Reconnaissance and Credential Access"
        elif bundle.detection_summary.get("privilege_escalation", 0):
            severity = "High"
            attack_type = "Privilege Escalation"
        elif bundle.detection_summary.get("multiple_failed_logins", 0):
            severity = "Medium"
            attack_type = "Credential Access Attempt"
        else:
            severity = "Low"
            attack_type = "Suspicious Activity"

        analysis = LLMAnalysisOutput(
            severity=severity,
            attack_type=attack_type,
            mitre_techniques=mitre,
            confidence_score=min(95, 55 + len(bundle.suspicious_events) * 5),
            analysis_summary="Benchmark analyzer produced a valid structured analysis for scenario evaluation.",
            recommended_actions=[
                "Review correlated evidence and validate exposure scope.",
                "Apply containment based on the highest-risk indicator or account.",
            ],
        )
        trace = LLMExecutionTrace(
            provider="benchmark_stub",
            model="deterministic-eval",
            prompt_version="benchmark-v1",
            used_fallback=False,
            fallback_reason=None,
            sanitized_bundle={
                "source_type": bundle.source_type,
                "detection_summary": bundle.detection_summary,
                "event_count": len(bundle.suspicious_events),
            },
            tasks=[
                LLMTaskTrace(
                    task_name="benchmark_analysis",
                    prompt_name="benchmark_stub",
                    raw_response=analysis.model_dump_json(),
                    used_fallback=False,
                )
            ],
        )
        return LLMAnalysisResult(analysis=analysis, trace=trace)


class BenchmarkService:
    def __init__(
        self,
        *,
        scenario_dir: str | Path | None = None,
        use_live_llm: bool = False,
    ) -> None:
        self.scenario_dir = Path(scenario_dir) if scenario_dir else Path(__file__).resolve().parents[2] / "scenarios"
        self.use_live_llm = use_live_llm

    def load_dataset(self, dataset_path: str | Path) -> BenchmarkDataset:
        dataset_file = Path(dataset_path)
        return BenchmarkDataset.model_validate(json.loads(dataset_file.read_text(encoding="utf-8")))

    def run_dataset(self, dataset: BenchmarkDataset) -> BenchmarkReport:
        case_results = [self._run_case(case.scenario_id, case.expected_severity, case.benign_expected) for case in dataset.cases]
        summary = self._summarize(case_results)
        return BenchmarkReport(
            generated_at=datetime.utcnow(),
            dataset_id=dataset.dataset_id,
            dataset_name=dataset.name,
            summary=summary,
            cases=case_results,
        )

    def render_markdown(self, report: BenchmarkReport) -> str:
        lines = [
            "# Benchmark Report",
            "",
            f"- Generated At: {report.generated_at.isoformat()}Z",
            f"- Dataset: {report.dataset_name} ({report.dataset_id})",
            "",
            "## Summary",
            "",
            f"- Total Cases: {report.summary.total_cases}",
            f"- Parser Success Rate: {report.summary.parser_success_rate:.2%}",
            f"- Detection Precision: {report.summary.detection_precision:.2%}",
            f"- Detection Recall: {report.summary.detection_recall:.2%}",
            f"- False Positive Rate: {report.summary.false_positive_rate:.2%}",
            f"- Severity Agreement: {report.summary.severity_agreement:.2%}",
            f"- MITRE Mapping Quality: {report.summary.mitre_mapping_quality:.2%}",
            f"- LLM Valid-Schema Rate: {report.summary.llm_valid_schema_rate:.2%}",
            f"- LLM Fallback Rate: {report.summary.llm_fallback_rate:.2%}",
            f"- Average Processing Time (ms): {report.summary.average_processing_time_ms:.2f}",
            f"- Average Review Time (minutes): {report.summary.average_review_time_minutes if report.summary.average_review_time_minutes is not None else 'n/a'}",
            "",
            "## Cases",
        ]
        for case in report.cases:
            lines.extend(
                [
                    "",
                    f"### {case.scenario_name} ({case.scenario_id})",
                    f"- Expected Severity: {case.expected_severity}",
                    f"- Actual Severity: {case.actual_severity}",
                    f"- Incidents: expected {case.expected_incident_count}, actual {case.actual_incident_count}",
                    f"- Correlated Incidents: expected {case.expected_correlated_incident_count}, actual {case.actual_correlated_incident_count}",
                    f"- Rule Hits: expected {', '.join(case.expected_rule_hits) or 'none'}, actual {', '.join(case.actual_rule_hits) or 'none'}",
                    f"- MITRE: expected {', '.join(case.expected_mitre_techniques) or 'none'}, actual {', '.join(case.actual_mitre_techniques) or 'none'}",
                    f"- Processing Time (ms): {case.processing_time_ms:.2f}",
                ]
            )
        return "\n".join(lines)

    def _run_case(self, scenario_id: str, expected_severity: str, benign_expected: bool) -> BenchmarkCaseResult:
        scenario = self._load_scenario(scenario_id)
        engine = create_engine("sqlite:///:memory:", future=True)
        session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
        Base.metadata.create_all(bind=engine)
        db: Session = session_factory()
        analyzer = ResilientLLMAnalyzer() if self.use_live_llm else BenchmarkLLMAnalyzer()
        pipeline = ProcessingPipelineService(llm_analyzer=analyzer)

        started = perf_counter()
        try:
            for upload in scenario.uploads:
                pipeline.process_new_upload(
                    db,
                    filename=upload.filename,
                    source_type=upload.source_type,
                    content=upload.content,
                )

            processing_time_ms = (perf_counter() - started) * 1000
            uploads = db.query(Upload).order_by(Upload.id).all()
            incidents = db.query(Incident).order_by(Incident.id).all()
            detections = db.query(DetectionRecord).order_by(DetectionRecord.id).all()
            llm_traces = db.query(IncidentEnrichment).filter(IncidentEnrichment.enrichment_type == "llm_execution_trace").all()
            analyst_reviews = db.query(AnalystReview).order_by(AnalystReview.created_at).all()

            total_lines = sum(upload.total_lines for upload in uploads)
            normalized_events = sum(upload.normalized_event_count for upload in uploads)
            parser_success_rate = normalized_events / total_lines if total_lines else 0.0

            actual_rule_hits = sorted({detection.rule_name for detection in detections})
            expected_rule_hits = scenario.expected_outcome.expected_rule_hits
            matched_rule_hits = len(set(expected_rule_hits) & set(actual_rule_hits))

            actual_mitre = self._actual_mitre_techniques(incidents)
            expected_mitre = scenario.expected_outcome.expected_mitre_techniques
            matched_mitre_hits = len(set(expected_mitre) & set(actual_mitre))

            actual_incident_count = len(incidents)
            actual_correlated_incident_count = sum(1 for incident in incidents if len(incident.upload_links) > 1)
            actual_severity = self._highest_severity(incidents)
            severity_match = actual_severity == expected_severity

            llm_valid_schema_count = sum(1 for trace in llm_traces if not trace.payload.get("used_fallback", False))
            llm_fallback_count = sum(1 for trace in llm_traces if trace.payload.get("used_fallback", False))
            average_review_time_minutes = self._average_review_time_minutes(uploads, analyst_reviews)

            return BenchmarkCaseResult(
                scenario_id=scenario.scenario_id,
                scenario_name=scenario.name,
                processing_time_ms=processing_time_ms,
                total_lines=total_lines,
                normalized_events=normalized_events,
                parser_success_rate=parser_success_rate,
                expected_incident_count=scenario.expected_outcome.expected_incident_count,
                actual_incident_count=actual_incident_count,
                expected_correlated_incident_count=scenario.expected_outcome.expected_correlated_incident_count,
                actual_correlated_incident_count=actual_correlated_incident_count,
                expected_rule_hits=expected_rule_hits,
                actual_rule_hits=actual_rule_hits,
                expected_mitre_techniques=expected_mitre,
                actual_mitre_techniques=actual_mitre,
                expected_severity=expected_severity,
                actual_severity=actual_severity,
                severity_match=severity_match,
                matched_rule_hits=matched_rule_hits,
                matched_mitre_hits=matched_mitre_hits,
                llm_valid_schema_count=llm_valid_schema_count,
                llm_fallback_count=llm_fallback_count,
                average_review_time_minutes=average_review_time_minutes,
            )
        finally:
            db.close()
            Base.metadata.drop_all(bind=engine)
            engine.dispose()

    def _summarize(self, case_results: list[BenchmarkCaseResult]) -> BenchmarkSummary:
        total_cases = len(case_results)
        total_lines = sum(case.total_lines for case in case_results)
        total_normalized = sum(case.normalized_events for case in case_results)
        total_detected_rule_hits = sum(len(case.actual_rule_hits) for case in case_results)
        total_expected_rule_hits = sum(len(case.expected_rule_hits) for case in case_results)
        total_matched_rule_hits = sum(case.matched_rule_hits for case in case_results)
        benign_cases = [case for case in case_results if not case.expected_rule_hits]
        benign_with_detections = [case for case in benign_cases if case.actual_rule_hits]
        total_expected_mitre_hits = sum(len(case.expected_mitre_techniques) for case in case_results)
        total_matched_mitre_hits = sum(case.matched_mitre_hits for case in case_results)
        total_llm_traces = sum(case.llm_valid_schema_count + case.llm_fallback_count for case in case_results)
        total_valid_llm = sum(case.llm_valid_schema_count for case in case_results)
        total_fallback_llm = sum(case.llm_fallback_count for case in case_results)
        review_times = [case.average_review_time_minutes for case in case_results if case.average_review_time_minutes is not None]

        return BenchmarkSummary(
            total_cases=total_cases,
            parser_success_rate=(total_normalized / total_lines) if total_lines else 0.0,
            detection_precision=(total_matched_rule_hits / total_detected_rule_hits) if total_detected_rule_hits else 0.0,
            detection_recall=(total_matched_rule_hits / total_expected_rule_hits) if total_expected_rule_hits else 0.0,
            false_positive_rate=(len(benign_with_detections) / len(benign_cases)) if benign_cases else 0.0,
            severity_agreement=(sum(1 for case in case_results if case.severity_match) / total_cases) if total_cases else 0.0,
            mitre_mapping_quality=(total_matched_mitre_hits / total_expected_mitre_hits) if total_expected_mitre_hits else 0.0,
            llm_valid_schema_rate=(total_valid_llm / total_llm_traces) if total_llm_traces else 0.0,
            llm_fallback_rate=(total_fallback_llm / total_llm_traces) if total_llm_traces else 0.0,
            average_processing_time_ms=(sum(case.processing_time_ms for case in case_results) / total_cases) if total_cases else 0.0,
            average_review_time_minutes=(sum(review_times) / len(review_times)) if review_times else None,
        )

    def _load_scenario(self, scenario_id: str) -> ScenarioPack:
        scenario_path = self.scenario_dir / f"{scenario_id}.json"
        return ScenarioPack.model_validate(json.loads(scenario_path.read_text(encoding="utf-8")))

    def _actual_mitre_techniques(self, incidents: list[Incident]) -> list[str]:
        techniques: set[str] = set()
        for incident in incidents:
            llm_enrichments = [
                enrichment for enrichment in incident.enrichments if enrichment.enrichment_type == "llm_analysis"
            ]
            for enrichment in llm_enrichments:
                for technique in enrichment.payload.get("mitre_techniques", []):
                    techniques.add(str(technique))
        return sorted(techniques)

    def _highest_severity(self, incidents: list[Incident]) -> str:
        if not incidents:
            return "Low"
        return max((incident.severity for incident in incidents), key=lambda severity: SEVERITY_ORDER.get(severity, 0))

    def _average_review_time_minutes(self, uploads: list[Upload], reviews: list[AnalystReview]) -> float | None:
        if not uploads or not reviews:
            return None
        first_upload_time = min(upload.uploaded_at for upload in uploads)
        first_review_time = min(review.created_at for review in reviews)
        return round((first_review_time - first_upload_time).total_seconds() / 60, 2)
