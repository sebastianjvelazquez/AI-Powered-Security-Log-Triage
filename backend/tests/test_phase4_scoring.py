from app.models.schemas import LLMAnalysisOutput
from app.scoring.engine import severity_from_score
from app.services.risk_scoring import build_incident_score


def test_build_incident_score_returns_component_breakdown() -> None:
    llm_output = LLMAnalysisOutput(
        severity="High",
        attack_type="Credential Access",
        mitre_techniques=["T1110"],
        confidence_score=86,
        analysis_summary="Structured detections indicate credential abuse activity with correlated evidence.",
        recommended_actions=["Block source IP", "Reset credentials"],
    )

    score = build_incident_score(
        rule_weights=[55, 60, 45],
        llm_analysis=llm_output,
        asset_criticality=2.0,
        suspicious_event_count=6,
        detection_summary={"multiple_failed_logins": 3, "suspicious_ip": 3},
        threat_intel_hits=1,
        correlation_strength=7,
    )

    assert score.total_score > 0
    assert score.severity == severity_from_score(score.total_score)
    assert score.scoring_version == "v2"
    assert len(score.breakdown) == 6
    assert score.summary.threat_intel_hits == 1
    assert score.summary.correlation_strength == 7


def test_build_incident_score_handles_empty_inputs() -> None:
    llm_output = LLMAnalysisOutput(
        severity="Low",
        attack_type="No suspicious activity",
        mitre_techniques=["T1595"],
        confidence_score=100,
        analysis_summary="No suspicious activity detected by deterministic controls.",
        recommended_actions=["Continue monitoring"],
    )

    score = build_incident_score(
        rule_weights=[],
        llm_analysis=llm_output,
        asset_criticality=1.0,
        suspicious_event_count=0,
        detection_summary={},
        threat_intel_hits=0,
        correlation_strength=0,
    )

    assert score.total_score >= 0
    assert score.summary.suspicious_event_count == 0
    assert score.summary.threat_intel_hits == 0
