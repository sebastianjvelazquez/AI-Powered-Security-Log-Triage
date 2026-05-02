from app.core.config import get_settings
from app.llm.analyzer import ResilientLLMAnalyzer, sanitize_bundle_for_prompt
from app.llm.factory import build_llm_provider
from app.llm.providers import HostedProvider, LLMProviderError, MockProvider
from app.models.schemas import IncidentBundle, SuspiciousEventOut


class FailingHostedProvider:
    provider_name = "hosted"
    model_name = "hosted-demo"

    def complete_task(self, *, task_name, prompt, safe_bundle):  # noqa: ANN001
        raise LLMProviderError(f"{task_name} unavailable")


def build_bundle() -> IncidentBundle:
    return IncidentBundle(
        source_type="auth",
        suspicious_events=[
            SuspiciousEventOut(
                timestamp="2026-03-01T10:00:00Z",
                source_ip="203.0.113.4",
                destination_ip="10.0.0.10",
                user="admin",
                event_type="authentication_failure",
                status="failed",
                rule_name="multiple_failed_logins",
                reason="Repeated failed logins from the same IP.",
                risk_weight=55,
                raw_message="failed login from 203.0.113.4",
            )
        ],
        detection_summary={"multiple_failed_logins": 1},
    )


def test_sanitized_bundle_excludes_raw_log_content() -> None:
    safe_bundle = sanitize_bundle_for_prompt(build_bundle())

    assert safe_bundle["suspicious_events"][0]["rule_name"] == "multiple_failed_logins"
    assert "raw_message" not in safe_bundle["suspicious_events"][0]


def test_factory_selects_mock_provider_when_configured(monkeypatch) -> None:  # noqa: ANN001
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_provider", "mock")

    provider = build_llm_provider()

    assert isinstance(provider, MockProvider)


def test_analyzer_supports_deterministic_only_mode(monkeypatch) -> None:  # noqa: ANN001
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_provider", "deterministic")
    analyzer = ResilientLLMAnalyzer()

    result = analyzer.analyze_with_fallback(build_bundle())

    assert result.trace.provider == "deterministic"
    assert result.trace.used_fallback is True
    assert result.analysis.attack_type == "Credential Access Attempt"


def test_provider_failure_falls_back_without_breaking_analysis() -> None:
    analyzer = ResilientLLMAnalyzer(provider=FailingHostedProvider())

    result = analyzer.analyze_with_fallback(build_bundle())

    assert result.trace.provider == "hosted"
    assert result.trace.used_fallback is True
    assert result.analysis.mitre_techniques == ["T1110"]
    assert all(task.used_fallback for task in result.trace.tasks)


def test_mock_provider_returns_valid_analysis_without_fallback() -> None:
    analyzer = ResilientLLMAnalyzer(provider=MockProvider())

    result = analyzer.analyze_with_fallback(build_bundle())

    assert result.trace.provider == "mock"
    assert result.trace.used_fallback is False
    assert result.analysis.attack_type == "Credential Access Attempt"


def test_hosted_provider_extracts_openai_chat_response(monkeypatch) -> None:  # noqa: ANN001
    settings = get_settings()
    monkeypatch.setattr(settings, "hosted_llm_base_url", "https://provider.example")
    monkeypatch.setattr(settings, "hosted_llm_endpoint", "/v1/chat/completions")
    monkeypatch.setattr(settings, "hosted_llm_api_style", "openai_chat")
    provider = HostedProvider()

    raw = provider._extract_response_text(
        {
            "choices": [
                {
                    "message": {
                        "content": "{\"attack_type\":\"Credential Access Attempt\",\"confidence_score\":82}"
                    }
                }
            ]
        },
        task_name="attack_classification",
    )

    assert raw == "{\"attack_type\":\"Credential Access Attempt\",\"confidence_score\":82}"


def test_hosted_provider_extracts_generic_json_field(monkeypatch) -> None:  # noqa: ANN001
    settings = get_settings()
    monkeypatch.setattr(settings, "hosted_llm_base_url", "https://provider.example")
    monkeypatch.setattr(settings, "hosted_llm_api_style", "generic_json")
    monkeypatch.setattr(settings, "hosted_llm_response_field", "output")
    provider = HostedProvider()

    raw = provider._extract_response_text(
        {"output": {"mitre_techniques": ["T1110"]}},
        task_name="mitre_mapping",
    )

    assert raw == "{\"mitre_techniques\": [\"T1110\"]}"
