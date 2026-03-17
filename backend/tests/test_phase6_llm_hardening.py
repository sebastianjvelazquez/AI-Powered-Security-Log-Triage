from app.llm.analyzer import ResilientLLMAnalyzer
from app.llm.validator import LLMValidationError
from app.models.schemas import IncidentBundle, LLMNarrativeOutput, LLMMitreMappingOutput, SuspiciousEventOut


class StubClient:
    model = "stub-model"

    def sanitize_bundle_for_prompt(self, bundle):  # noqa: ANN001
        return {
            "source_type": bundle.source_type,
            "detection_summary": bundle.detection_summary,
            "suspicious_events": [event.model_dump(mode="json") for event in bundle.suspicious_events],
        }

    def classify_attack(self, safe_bundle):  # noqa: ANN001
        raise LLMValidationError("classification returned invalid schema")

    def map_mitre(self, safe_bundle):  # noqa: ANN001
        return LLMMitreMappingOutput(mitre_techniques=["T1110"]), "{\"mitre_techniques\":[\"T1110\"]}"

    def summarize_for_analyst(self, safe_bundle):  # noqa: ANN001
        return (
            LLMNarrativeOutput(
                analysis_summary="Structured detections indicate likely credential abuse requiring analyst review.",
                recommended_actions=["Reset affected credentials", "Block the source IP"],
            ),
            "{\"analysis_summary\":\"Structured detections indicate likely credential abuse requiring analyst review.\",\"recommended_actions\":[\"Reset affected credentials\",\"Block the source IP\"]}",
        )


def test_resilient_analyzer_falls_back_per_task() -> None:
    analyzer = ResilientLLMAnalyzer()
    analyzer.client = StubClient()
    bundle = IncidentBundle(
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

    result = analyzer.analyze_with_fallback(bundle)

    assert result.trace.used_fallback is True
    assert result.analysis.attack_type == "Credential Access Attempt"
    assert result.analysis.mitre_techniques == ["T1110"]
    assert any(task.task_name == "attack_classification" and task.used_fallback for task in result.trace.tasks)
