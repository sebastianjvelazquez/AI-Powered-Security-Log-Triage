from app.models.schemas import LLMAnalysisOutput


def compute_risk_score(rule_weights: list[int], llm_analysis: LLMAnalysisOutput, asset_criticality: float) -> float:
    if not rule_weights:
        return 0.0

    rule_component = min(70.0, sum(rule_weights) * 0.6)
    confidence_component = llm_analysis.confidence_score * 0.2
    criticality_component = min(15.0, asset_criticality * 5.0)

    score = min(100.0, rule_component + confidence_component + criticality_component)
    return round(score, 2)


def severity_from_score(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"
