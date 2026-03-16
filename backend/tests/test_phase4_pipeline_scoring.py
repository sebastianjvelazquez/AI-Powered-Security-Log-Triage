from app.models.db_models import IncidentScore
from app.models.schemas import LLMAnalysisOutput
from app.services.processing_pipeline_service import ProcessingPipelineService


class StubAnalyzer:
    def analyze_with_fallback(self, bundle):  # noqa: ANN001
        return LLMAnalysisOutput(
            severity="High",
            attack_type="Credential Access",
            mitre_techniques=["T1110"],
            confidence_score=84,
            analysis_summary="Repeated failed logins from a suspicious source indicate credential access activity.",
            recommended_actions=["Block the source IP.", "Reset affected credentials."],
        )


def test_pipeline_persists_explainable_score_breakdown(db_session) -> None:
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

    score = db_session.query(IncidentScore).one()

    assert result.risk_score == score.total_score
    assert score.scoring_version == "v2"
    assert "breakdown" in score.score_breakdown
    assert "summary" in score.score_breakdown
    assert len(score.score_breakdown["breakdown"]) == 6
