from __future__ import annotations

from dataclasses import dataclass

from app.models.schemas import LLMAnalysisOutput


@dataclass
class ScoringInputs:
    rule_weights: list[int]
    asset_criticality: float
    event_frequency: int
    threat_intel_hits: int
    llm_confidence: int
    correlation_strength: int


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def score_rule_severity(rule_weights: list[int]) -> tuple[float, str]:
    if not rule_weights:
        return 0.0, "No detections contributed to the incident score."

    raw_score = sum(rule_weights) / max(len(rule_weights), 1)
    score = round(_clamp(raw_score * 0.45, 0.0, 30.0), 2)
    rationale = f"Average detection weight {round(raw_score, 2)} derived from {len(rule_weights)} triggered rules."
    return score, rationale


def score_asset_criticality(asset_criticality: float) -> tuple[float, str]:
    score = round(_clamp(asset_criticality * 6.0, 0.0, 18.0), 2)
    rationale = f"Asset criticality multiplier {asset_criticality} contributes proportionally to incident risk."
    return score, rationale


def score_event_frequency(event_frequency: int) -> tuple[float, str]:
    score = round(_clamp(event_frequency * 1.5, 0.0, 12.0), 2)
    rationale = f"{event_frequency} suspicious events contribute repetition-based risk."
    return score, rationale


def score_threat_intel(threat_intel_hits: int) -> tuple[float, str]:
    score = round(_clamp(threat_intel_hits * 7.5, 0.0, 20.0), 2)
    rationale = (
        f"{threat_intel_hits} threat-intel hit(s) increased score."
        if threat_intel_hits
        else "No threat-intel hits were available at scoring time."
    )
    return score, rationale


def score_llm_confidence(llm_analysis: LLMAnalysisOutput) -> tuple[float, str]:
    score = round(_clamp(llm_analysis.confidence_score * 0.12, 0.0, 12.0), 2)
    rationale = f"Validated LLM confidence of {llm_analysis.confidence_score} influenced analyst-summary confidence only."
    return score, rationale


def score_correlation_strength(correlation_strength: int) -> tuple[float, str]:
    score = round(_clamp(float(correlation_strength), 0.0, 8.0), 2)
    rationale = (
        f"Correlation engine contributed {correlation_strength} points based on cross-source or chain evidence."
        if correlation_strength
        else "No cross-source correlation strength was applied."
    )
    return score, rationale


def severity_from_score(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"
