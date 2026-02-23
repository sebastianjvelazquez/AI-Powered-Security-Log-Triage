import json

from pydantic import ValidationError

from app.models.schemas import LLMAnalysisOutput


class LLMValidationError(Exception):
    """Raised when model output fails strict schema validation."""


def validate_llm_response(raw_text: str) -> LLMAnalysisOutput:
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise LLMValidationError(f"Invalid JSON from LLM: {exc}") from exc

    try:
        return LLMAnalysisOutput.model_validate(data)
    except ValidationError as exc:
        raise LLMValidationError(f"LLM output schema validation failed: {exc}") from exc
