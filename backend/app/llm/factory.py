from __future__ import annotations

from app.core.config import get_settings
from app.llm.providers import HostedProvider, LLMProvider, MockProvider, OllamaProvider


def build_llm_provider() -> LLMProvider | None:
    settings = get_settings()
    mode = settings.llm_provider.strip().lower()

    if mode == "deterministic":
        return None
    if mode == "ollama":
        return OllamaProvider()
    if mode == "hosted":
        return HostedProvider()
    if mode == "mock":
        return MockProvider()

    raise ValueError(f"Unsupported LLM provider mode: {mode}")
