from __future__ import annotations

from app.core.config import Settings


def validate_startup_configuration(settings: Settings) -> None:
    tokens = {
        "viewer_api_token": settings.viewer_api_token.strip(),
        "analyst_api_token": settings.analyst_api_token.strip(),
        "admin_api_token": settings.admin_api_token.strip(),
    }

    if any(not token for token in tokens.values()):
        raise RuntimeError("All API tokens must be configured and non-empty.")

    if len(set(tokens.values())) != len(tokens):
        raise RuntimeError("Viewer, analyst, and admin API tokens must be unique.")

    if not settings.allowed_extension_set():
        raise RuntimeError("At least one allowed upload extension must be configured.")

    if not settings.allowed_mime_type_set():
        raise RuntimeError("At least one allowed upload MIME type must be configured.")

    if settings.enable_pii_redaction and not settings.pii_redaction_salt.strip():
        raise RuntimeError("PII_REDACTION_SALT is required when ENABLE_PII_REDACTION is enabled.")

    llm_provider = settings.llm_provider.strip().lower()
    if llm_provider not in {"ollama", "hosted", "mock", "deterministic"}:
        raise RuntimeError("LLM_PROVIDER must be one of: ollama, hosted, mock, deterministic.")

    if not settings.llm_prompt_version.strip():
        raise RuntimeError("LLM_PROMPT_VERSION must be configured.")

    if llm_provider == "ollama" and not settings.ollama_base_url.strip():
        raise RuntimeError("OLLAMA_BASE_URL is required when LLM_PROVIDER=ollama.")

    if llm_provider == "hosted":
        if not settings.hosted_llm_base_url.strip():
            raise RuntimeError("HOSTED_LLM_BASE_URL is required when LLM_PROVIDER=hosted.")
        if not settings.hosted_llm_endpoint.strip():
            raise RuntimeError("HOSTED_LLM_ENDPOINT is required when LLM_PROVIDER=hosted.")
        if not settings.hosted_llm_response_field.strip():
            raise RuntimeError("HOSTED_LLM_RESPONSE_FIELD is required when LLM_PROVIDER=hosted.")
