import json

from pydantic import ValidationError

from app.models.schemas import LLMAnalysisOutput, LLMClassificationOutput, LLMMitreMappingOutput, LLMNarrativeOutput
from app.utils.mitre import filter_allowed_mitre_ids


class LLMValidationError(Exception):
    """Raised when model output fails strict schema validation."""


def _parse_json(raw_text: str) -> dict:
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise LLMValidationError(f"Invalid JSON from LLM: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LLMValidationError("LLM output must be a JSON object.")
    return parsed


def validate_llm_response(raw_text: str) -> LLMAnalysisOutput:
    data = _parse_json(raw_text)

    try:
        return LLMAnalysisOutput.model_validate(data)
    except ValidationError as exc:
        raise LLMValidationError(f"LLM output schema validation failed: {exc}") from exc


def validate_classification_response(raw_text: str) -> LLMClassificationOutput:
    data = _parse_json(raw_text)
    try:
        return LLMClassificationOutput.model_validate(data)
    except ValidationError as exc:
        raise LLMValidationError(f"LLM classification schema validation failed: {exc}") from exc


def validate_mitre_mapping_response(raw_text: str) -> LLMMitreMappingOutput:
    data = _parse_json(raw_text)
    try:
        parsed = LLMMitreMappingOutput.model_validate(data)
    except ValidationError as exc:
        raise LLMValidationError(f"LLM MITRE schema validation failed: {exc}") from exc

    filtered = filter_allowed_mitre_ids(parsed.mitre_techniques)
    if not filtered:
        raise LLMValidationError("LLM MITRE output did not contain allowlisted techniques.")
    return parsed.model_copy(update={"mitre_techniques": filtered})


def validate_narrative_response(raw_text: str) -> LLMNarrativeOutput:
    data = _parse_json(raw_text)
    try:
        return LLMNarrativeOutput.model_validate(data)
    except ValidationError as exc:
        raise LLMValidationError(f"LLM narrative schema validation failed: {exc}") from exc
