from fastapi import APIRouter, Depends

from app.core.auth import require_role
from app.core.config import get_settings
from app.core.rate_limit import enforce_rate_limit
from app.models.enums import UserRole
from app.models.schemas import AIProviderStatusResponse

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/ai-status", response_model=AIProviderStatusResponse)
def get_ai_status(
    _: None = Depends(enforce_rate_limit("read")),
    __=Depends(require_role(UserRole.VIEWER)),
) -> AIProviderStatusResponse:
    settings = get_settings()
    provider = settings.llm_provider.strip().lower()
    notes = [
        "Deterministic parsing, detection, correlation, and scoring remain active regardless of provider mode.",
        "Only sanitized incident bundles are sent to configured AI providers.",
    ]

    configured = True
    model = "deterministic-fallback"
    hosted_api_style = None

    if provider == "ollama":
        model = settings.ollama_model
        configured = bool(settings.ollama_base_url.strip())
    elif provider == "hosted":
        model = settings.hosted_llm_model
        hosted_api_style = settings.hosted_llm_api_style.strip().lower()
        configured = bool(settings.hosted_llm_base_url.strip() and settings.hosted_llm_endpoint.strip())
    elif provider == "mock":
        model = "mock-triage-provider"
    elif provider != "deterministic":
        configured = False

    mode_labels = {
        "deterministic": "Deterministic only",
        "ollama": "Local Ollama",
        "hosted": "Hosted API",
        "mock": "Mock provider",
    }

    return AIProviderStatusResponse(
        provider=provider,
        mode_label=mode_labels.get(provider, "Unknown"),
        model=model,
        prompt_version=settings.llm_prompt_version,
        configured=configured,
        deterministic_fallback_available=True,
        raw_logs_sent_to_provider=False,
        hosted_api_style=hosted_api_style,
        notes=notes,
    )
