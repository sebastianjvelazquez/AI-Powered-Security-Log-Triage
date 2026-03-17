import pytest

from app.llm.validator import (
    LLMValidationError,
    validate_classification_response,
    validate_llm_response,
    validate_mitre_mapping_response,
    validate_narrative_response,
)


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


def test_validate_mitre_mapping_response_rejects_non_allowlisted_ids() -> None:
    raw = """
    {
      "mitre_techniques": ["T9999"]
    }
    """

    with pytest.raises(LLMValidationError):
        validate_mitre_mapping_response(raw)


def test_validate_task_specific_responses() -> None:
    classification = validate_classification_response(
        """
        {
          "attack_type": "Credential Access Attempt",
          "confidence_score": 73
        }
        """
    )
    narrative = validate_narrative_response(
        """
        {
          "analysis_summary": "Correlated authentication failures indicate likely credential abuse activity requiring analyst review.",
          "recommended_actions": ["Reset targeted credentials", "Review source IP activity"]
        }
        """
    )

    assert classification.attack_type == "Credential Access Attempt"
    assert classification.confidence_score == 73
    assert len(narrative.recommended_actions) == 2
