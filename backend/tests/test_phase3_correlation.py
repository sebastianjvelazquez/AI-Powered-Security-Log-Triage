from app.models.db_models import Incident, IncidentUploadLink
from app.models.schemas import LLMAnalysisOutput
from app.services.processing_pipeline_service import ProcessingPipelineService


class StubAnalyzer:
    def analyze_with_fallback(self, bundle):  # noqa: ANN001
        return LLMAnalysisOutput(
            severity="High",
            attack_type="Credential Access",
            mitre_techniques=["T1110"],
            confidence_score=88,
            analysis_summary="Deterministic detections indicate coordinated attack activity across the observed telemetry.",
            recommended_actions=["Block the source IP.", "Reset or lock affected accounts."],
        )


def test_correlation_reuses_incident_for_port_scan_then_failed_logins(db_session) -> None:
    service = ProcessingPipelineService(llm_analyzer=StubAnalyzer())

    firewall_content = "\n".join(
        [
            "2026-02-22T10:10:00Z FW DROP SRC=198.51.100.77 DST=10.0.0.5 DPT=22 PROTO=TCP",
            "2026-02-22T10:10:01Z FW DROP SRC=198.51.100.77 DST=10.0.0.5 DPT=80 PROTO=TCP",
            "2026-02-22T10:10:02Z FW DROP SRC=198.51.100.77 DST=10.0.0.5 DPT=443 PROTO=TCP",
            "2026-02-22T10:10:03Z FW DROP SRC=198.51.100.77 DST=10.0.0.5 DPT=3389 PROTO=TCP",
            "2026-02-22T10:10:04Z FW DROP SRC=198.51.100.77 DST=10.0.0.5 DPT=8080 PROTO=TCP",
        ]
    )
    auth_content = "\n".join(
        [
            "2026-02-22T10:12:13Z host-a sshd[1245]: Failed password for invalid user admin from 198.51.100.77 port 50123 ssh2",
            "2026-02-22T10:12:14Z host-a sshd[1246]: Failed password for invalid user admin from 198.51.100.77 port 50124 ssh2",
            "2026-02-22T10:12:15Z host-a sshd[1247]: Failed password for invalid user admin from 198.51.100.77 port 50125 ssh2",
        ]
    )

    firewall_result = service.process_new_upload(
        db_session,
        filename="firewall.log",
        source_type="firewall",
        content=firewall_content,
    )
    auth_result = service.process_new_upload(
        db_session,
        filename="auth.log",
        source_type="auth",
        content=auth_content,
    )

    assert firewall_result.incident_id == auth_result.incident_id

    incidents = db_session.query(Incident).all()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.correlation_summary is not None
    assert "port_scan_followed_by_auth_abuse" in incident.correlation_context["chains"]
    assert sorted(incident.source_types) == ["auth", "firewall"]
    assert db_session.query(IncidentUploadLink).count() == 2


def test_correlation_reuses_incident_for_failed_logins_then_privilege_action_same_user(db_session) -> None:
    service = ProcessingPipelineService(llm_analyzer=StubAnalyzer())

    auth_content = "\n".join(
        [
            "2026-02-22T11:02:13Z host-b sshd[1245]: Failed password for invalid user jdoe from 203.0.113.55 port 50123 ssh2",
            "2026-02-22T11:02:14Z host-b sshd[1246]: Failed password for invalid user jdoe from 203.0.113.55 port 50124 ssh2",
            "2026-02-22T11:02:15Z host-b sshd[1247]: Failed password for invalid user jdoe from 203.0.113.55 port 50125 ssh2",
        ]
    )
    windows_content = "2026-02-22T11:04:10Z EventID=4672 User=jdoe SrcIP=203.0.113.55 Status=SUCCESS Message=Special admin privileges assigned"

    auth_result = service.process_new_upload(
        db_session,
        filename="auth.log",
        source_type="auth",
        content=auth_content,
    )
    windows_result = service.process_new_upload(
        db_session,
        filename="windows.log",
        source_type="windows",
        content=windows_content,
    )

    assert auth_result.incident_id == windows_result.incident_id
    incident = db_session.query(Incident).one()
    assert "failed_logins_followed_by_privilege_action" in incident.correlation_context["chains"]
    assert incident.correlation_summary is not None
