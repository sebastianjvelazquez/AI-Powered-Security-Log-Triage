import pytest

from app.models.db_models import AnalystReview, AuditLog, Incident
from app.models.schemas import AnalystReviewCreateRequest, IncidentStatusUpdateRequest, LLMAnalysisOutput
from app.services.analyst_workflow_service import AnalystWorkflowService, InvalidIncidentTransitionError
from app.services.processing_pipeline_service import ProcessingPipelineService


class StubAnalyzer:
    def analyze_with_fallback(self, bundle):  # noqa: ANN001
        return LLMAnalysisOutput(
            severity="High",
            attack_type="Credential Access",
            mitre_techniques=["T1110"],
            confidence_score=80,
            analysis_summary="Repeated failed logins indicate likely credential abuse activity requiring analyst triage.",
            recommended_actions=["Block the source IP.", "Reset affected credentials."],
        )


def _create_incident(db_session) -> int:
    service = ProcessingPipelineService(llm_analyzer=StubAnalyzer())
    content = "\n".join(
        [
            "2026-02-22T10:02:13Z host-a sshd[1245]: Failed password for invalid user admin from 203.0.113.4 port 50123 ssh2",
            "2026-02-22T10:02:14Z host-a sshd[1246]: Failed password for invalid user admin from 203.0.113.4 port 50124 ssh2",
            "2026-02-22T10:02:15Z host-a sshd[1247]: Failed password for invalid user admin from 203.0.113.4 port 50125 ssh2",
        ]
    )
    result = service.process_new_upload(
        db_session,
        filename="auth.log",
        source_type="auth",
        content=content,
    )
    return result.incident_id


def test_submit_review_persists_override_and_audit_log(db_session) -> None:
    incident_id = _create_incident(db_session)
    workflow_service = AnalystWorkflowService()

    detail = workflow_service.submit_review(
        db_session,
        incident_id=incident_id,
        review_request=AnalystReviewCreateRequest(
            reviewer="analyst@example.com",
            disposition="escalated",
            notes="Cross-source login abuse warrants escalation.",
            override_severity="Critical",
            override_mitre_techniques=["T1110"],
            override_recommended_actions=["Disable the targeted account.", "Block the source IP."],
        ),
    )

    assert detail is not None
    assert detail.status == "escalated"
    assert detail.effective_severity == "Critical"
    assert detail.latest_disposition == "escalated"
    assert detail.effective_mitre_techniques == ["T1110"]
    assert "Disable the targeted account." in detail.effective_recommended_actions
    assert any(log.action == "incident.review_submitted" for log in detail.audit_logs)
    assert any(log.action == "incident.severity_overridden" for log in detail.audit_logs)

    persisted_incident = db_session.query(Incident).filter(Incident.id == incident_id).one()
    persisted_review = db_session.query(AnalystReview).filter(AnalystReview.incident_id == incident_id).one()
    analyst_logs = db_session.query(AuditLog).filter(AuditLog.incident_id == incident_id, AuditLog.actor == "analyst@example.com").all()

    assert persisted_incident.status == "escalated"
    assert persisted_incident.severity == "Critical"
    assert persisted_review.disposition == "escalated"
    assert len(analyst_logs) >= 3


def test_invalid_status_transition_is_rejected(db_session) -> None:
    incident_id = _create_incident(db_session)
    workflow_service = AnalystWorkflowService()

    first_detail = workflow_service.submit_review(
        db_session,
        incident_id=incident_id,
        review_request=AnalystReviewCreateRequest(
            reviewer="analyst@example.com",
            disposition="false_positive",
            notes="Benign noisy admin activity.",
        ),
    )
    assert first_detail is not None
    assert first_detail.status == "false_positive"

    with pytest.raises(InvalidIncidentTransitionError):
        workflow_service.update_status(
            db_session,
            incident_id=incident_id,
            status_request=IncidentStatusUpdateRequest(
                reviewer="analyst@example.com",
                status="escalated",
                notes="This should be rejected from false_positive without reopening first.",
            ),
        )
