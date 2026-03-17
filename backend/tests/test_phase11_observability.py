from pathlib import Path

from app.models.schemas import AnalystReviewCreateRequest, LLMAnalysisOutput
from app.observability.metrics import metrics_registry
from app.services.analyst_workflow_service import AnalystWorkflowService
from app.services.processing_pipeline_service import ProcessingPipelineService
from app.services.upload_job_service import UploadJobService
from app.utils.upload_storage import UploadStorage


class StubAnalyzer:
    def analyze_with_fallback(self, bundle):  # noqa: ANN001
        return LLMAnalysisOutput(
            severity="High",
            attack_type="Credential Access",
            mitre_techniques=["T1110"],
            confidence_score=88,
            analysis_summary="Repeated failed logins indicate likely credential abuse activity requiring analyst review.",
            recommended_actions=["Block the source IP.", "Reset affected credentials."],
        )


def test_upload_service_emits_upload_metric(db_session, tmp_path: Path) -> None:
    service = UploadJobService(storage=UploadStorage(str(tmp_path)))

    service.stage_upload(
        db_session,
        filename="auth.log",
        source_type="auth",
        content=b"2026-02-22T10:02:13Z host sshd[1245]: Failed password for invalid user admin from 203.0.113.4 port 50123 ssh2",
    )

    rendered = metrics_registry.render_prometheus()

    assert 'uploads_total{source_type="auth"} 1.0' in rendered
    assert 'upload_stage_duration_seconds_count{source_type="auth"} 1' in rendered


def test_pipeline_and_review_emit_observability_metrics(db_session) -> None:
    pipeline = ProcessingPipelineService(llm_analyzer=StubAnalyzer())
    response = pipeline.process_new_upload(
        db_session,
        filename="auth.log",
        source_type="auth",
        content="\n".join(
            [
                "2026-02-22T10:02:13Z host sshd[1245]: Failed password for invalid user admin from 203.0.113.4 port 50123 ssh2",
                "2026-02-22T10:02:14Z host sshd[1246]: Failed password for invalid user admin from 203.0.113.4 port 50124 ssh2",
                "2026-02-22T10:02:15Z host sshd[1247]: Failed password for invalid user admin from 203.0.113.4 port 50125 ssh2",
            ]
        ),
    )

    workflow = AnalystWorkflowService()
    workflow.submit_review(
        db_session,
        incident_id=response.incident_id,
        review_request=AnalystReviewCreateRequest(
            reviewer="analyst@example.com",
            disposition="needs_review",
            notes="Escalation pending further evidence.",
        ),
    )

    rendered = metrics_registry.render_prometheus()

    assert 'detections_fired_total{source_type="auth"}' in rendered
    assert 'incidents_created_total{source_type="auth"} 1.0' in rendered
    assert 'incident_score_distribution_total{severity="Medium"} 1.0' in rendered or 'incident_score_distribution_total{severity="High"} 1.0' in rendered or 'incident_score_distribution_total{severity="Critical"} 1.0' in rendered
    assert 'review_counts_total{disposition="needs_review"} 1.0' in rendered
    assert 'pipeline_run_duration_seconds_count{source_type="auth"} 1' in rendered
