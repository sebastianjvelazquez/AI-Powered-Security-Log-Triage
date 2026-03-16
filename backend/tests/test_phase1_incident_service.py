from app.models.db_models import AuditLog, DetectionRecord, IOCache, Incident, IncidentEnrichment, IncidentScore, NormalizedEventRecord, Upload
from app.models.schemas import LLMAnalysisOutput
from app.services.incident_service import IncidentService


class StubAnalyzer:
    def analyze_with_fallback(self, bundle):  # noqa: ANN001
        return LLMAnalysisOutput(
            severity="High",
            attack_type="Credential Access",
            mitre_techniques=["T1110"],
            confidence_score=84,
            analysis_summary="Repeated failed logins from a flagged source indicate likely credential access activity.",
            recommended_actions=["Block the source IP.", "Reset affected credentials."],
        )


def test_process_upload_persists_incident_graph(db_session) -> None:
    service = IncidentService(llm_analyzer=StubAnalyzer())
    content = "\n".join(
        [
            "2026-02-22T10:02:13Z host sshd[1245]: Failed password for invalid user admin from 203.0.113.4 port 50123 ssh2",
            "2026-02-22T10:02:14Z host sshd[1246]: Failed password for invalid user admin from 203.0.113.4 port 50124 ssh2",
            "2026-02-22T10:02:15Z host sshd[1247]: Failed password for invalid user admin from 203.0.113.4 port 50125 ssh2",
        ]
    )

    response = service.process_upload(db_session, filename="auth.log", source_type="auth", content=content)

    assert response.upload_id > 0
    assert response.incident_id > 0
    assert response.suspicious_count >= 1
    assert response.status == "new"

    assert db_session.query(Upload).count() == 1
    assert db_session.query(NormalizedEventRecord).count() == 3
    assert db_session.query(DetectionRecord).count() >= 1
    assert db_session.query(Incident).count() == 1
    assert db_session.query(IncidentEnrichment).count() == 1
    assert db_session.query(IncidentScore).count() == 1
    assert db_session.query(AuditLog).count() >= 2
    assert db_session.query(IOCache).count() == 1


def test_process_upload_without_detections_still_creates_low_incident(db_session) -> None:
    service = IncidentService(llm_analyzer=StubAnalyzer())
    content = "2026-02-22T10:02:13Z host sshd[1245]: Accepted password for root from 10.0.0.10 port 50123 ssh2"

    response = service.process_upload(db_session, filename="clean.log", source_type="auth", content=content)

    assert response.severity == "Low"
    assert response.suspicious_count == 0
    assert db_session.query(Incident).count() == 1
    assert db_session.query(DetectionRecord).count() == 0
