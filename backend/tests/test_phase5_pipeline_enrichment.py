from app.models.db_models import IOCache, IncidentEnrichment, IncidentScore
from app.services.processing_pipeline_service import ProcessingPipelineService


class StubAnalyzer:
    def analyze_with_fallback(self, bundle):  # noqa: ANN001
        from app.models.schemas import LLMAnalysisOutput

        return LLMAnalysisOutput(
            severity="High",
            attack_type="Credential Access",
            mitre_techniques=["T1110"],
            confidence_score=84,
            analysis_summary="Repeated failed logins from a suspicious source indicate credential access activity.",
            recommended_actions=["Block the source IP.", "Reset affected credentials."],
        )


def test_pipeline_persists_threat_intel_enrichment_and_scores(db_session) -> None:
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

    threat_intel_enrichment = (
        db_session.query(IncidentEnrichment).filter(IncidentEnrichment.enrichment_type == "threat_intel").one()
    )
    current_score = db_session.query(IncidentScore).filter(IncidentScore.is_current.is_(True)).one()
    threat_intel_ioc = db_session.query(IOCache).filter(IOCache.source == "local_mock_threat_intel").one()

    assert result.risk_score == current_score.total_score
    assert threat_intel_enrichment.provider == "local_mock_threat_intel"
    assert threat_intel_enrichment.payload["summary"]["malicious_indicator_count"] == 1
    assert current_score.score_breakdown["summary"]["threat_intel_hits"] == 1
    assert threat_intel_ioc.indicator == "203.0.113.4"
