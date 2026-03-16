from app.models.schemas import IncidentScoreBreakdown, IncidentScoreSummary, IncidentScoreView, LLMAnalysisOutput
from app.scoring.engine import (
    ScoringInputs,
    score_asset_criticality,
    score_correlation_strength,
    score_event_frequency,
    score_llm_confidence,
    score_rule_severity,
    score_threat_intel,
    severity_from_score,
)

def build_incident_score(
    *,
    rule_weights: list[int],
    llm_analysis: LLMAnalysisOutput,
    asset_criticality: float,
    suspicious_event_count: int,
    detection_summary: dict[str, int],
    threat_intel_hits: int,
    correlation_strength: int,
    scoring_version: str = "v2",
) -> IncidentScoreView:
    inputs = ScoringInputs(
        rule_weights=rule_weights,
        asset_criticality=asset_criticality,
        event_frequency=suspicious_event_count,
        threat_intel_hits=threat_intel_hits,
        llm_confidence=llm_analysis.confidence_score,
        correlation_strength=correlation_strength,
    )

    rule_score, rule_reason = score_rule_severity(inputs.rule_weights)
    asset_score, asset_reason = score_asset_criticality(inputs.asset_criticality)
    frequency_score, frequency_reason = score_event_frequency(inputs.event_frequency)
    threat_score, threat_reason = score_threat_intel(inputs.threat_intel_hits)
    llm_score, llm_reason = score_llm_confidence(llm_analysis)
    correlation_score, correlation_reason = score_correlation_strength(inputs.correlation_strength)

    total_score = round(rule_score + asset_score + frequency_score + threat_score + llm_score + correlation_score, 2)
    severity = severity_from_score(total_score)

    breakdown = [
        IncidentScoreBreakdown(component="rule_severity", score=rule_score, max_score=30.0, rationale=rule_reason),
        IncidentScoreBreakdown(component="asset_criticality", score=asset_score, max_score=18.0, rationale=asset_reason),
        IncidentScoreBreakdown(component="event_frequency", score=frequency_score, max_score=12.0, rationale=frequency_reason),
        IncidentScoreBreakdown(component="threat_intel", score=threat_score, max_score=20.0, rationale=threat_reason),
        IncidentScoreBreakdown(component="llm_confidence", score=llm_score, max_score=12.0, rationale=llm_reason),
        IncidentScoreBreakdown(component="correlation_strength", score=correlation_score, max_score=8.0, rationale=correlation_reason),
    ]

    return IncidentScoreView(
        total_score=total_score,
        severity=severity,
        scoring_version=scoring_version,
        breakdown=breakdown,
        summary=IncidentScoreSummary(
            suspicious_event_count=suspicious_event_count,
            detection_summary=detection_summary,
            threat_intel_hits=threat_intel_hits,
            correlation_strength=correlation_strength,
        ),
    )
