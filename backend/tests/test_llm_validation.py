import pytest

from app.llm.validator import LLMValidationError, validate_llm_response


def test_validate_llm_response_valid_json() -> None:
    raw = """
    {
      "severity": "High",
      "attack_type": "Brute Force Attempt",
      "mitre_techniques": ["T1110"],
      "confidence_score": 82,
      "analysis_summary": "Multiple failed authentication attempts indicate probable brute-force activity against exposed service credentials.",
      "recommended_actions": ["Block source IP", "Enable MFA"]
    }
    """

    parsed = validate_llm_response(raw)

    assert parsed.severity == "High"
    assert parsed.confidence_score == 82


def test_validate_llm_response_rejects_invalid_schema() -> None:
    raw = """
    {
      "severity": "Severe",
      "attack_type": "Unknown",
      "mitre_techniques": ["1110"],
      "confidence_score": 101,
      "analysis_summary": "short",
      "recommended_actions": []
    }
    """

    with pytest.raises(LLMValidationError):
        validate_llm_response(raw)
