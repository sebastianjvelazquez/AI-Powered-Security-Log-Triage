from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, TypeVar

from app.core.config import get_settings
from app.llm.factory import build_llm_provider
from app.llm.providers import LLMProvider, LLMProviderError
from app.llm.validator import (
    LLMValidationError,
    validate_classification_response,
    validate_mitre_mapping_response,
    validate_narrative_response,
)
from app.models.schemas import (
    IncidentBundle,
    LLMAnalysisOutput,
    LLMAnalysisResult,
    LLMClassificationOutput,
    LLMExecutionTrace,
    LLMMitreMappingOutput,
    LLMNarrativeOutput,
    LLMTaskTrace,
)
from app.observability.logging import get_logger, log_event
from app.observability.metrics import metrics_registry
from app.utils.mitre import map_rules_to_mitre

settings = get_settings()
logger = get_logger(__name__)

PROMPT_DIR = Path(__file__).with_name("prompts")

TaskModel = TypeVar("TaskModel", LLMClassificationOutput, LLMMitreMappingOutput, LLMNarrativeOutput)


def sanitize_bundle_for_prompt(bundle: IncidentBundle) -> dict[str, Any]:
    sanitized_events = []
    for event in bundle.suspicious_events:
        sanitized_events.append(
            {
                "timestamp": event.timestamp,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "user": event.user,
                "event_type": event.event_type,
                "status": event.status,
                "rule_name": event.rule_name,
                "reason": event.reason,
                "risk_weight": event.risk_weight,
            }
        )

    return {
        "source_type": bundle.source_type,
        "detection_summary": bundle.detection_summary,
        "suspicious_events": sanitized_events,
    }


class ResilientLLMAnalyzer:
    def __init__(self, provider: LLMProvider | None = None) -> None:
        self._provider = provider if provider is not None else build_llm_provider()

    @property
    def provider(self) -> LLMProvider | None:
        return self._provider

    @provider.setter
    def provider(self, value: LLMProvider | None) -> None:
        self._provider = value

    @property
    def client(self) -> LLMProvider | None:
        return self._provider

    @client.setter
    def client(self, value: LLMProvider | None) -> None:
        self._provider = value

    def _load_prompt_template(self, prompt_name: str) -> str:
        prompt_path = PROMPT_DIR / prompt_name
        return prompt_path.read_text(encoding="utf-8")

    def _render_prompt(self, prompt_name: str, safe_bundle: dict[str, Any]) -> str:
        prompt_template = self._load_prompt_template(prompt_name)
        return prompt_template.format(incident_bundle_json=json.dumps(safe_bundle, separators=(",", ":")))

    def analyze_with_fallback(self, bundle: IncidentBundle) -> LLMAnalysisResult:
        safe_bundle = sanitize_bundle_for_prompt(bundle)

        if self.provider is None:
            return self._deterministic_only_result(bundle, safe_bundle)

        task_traces: list[LLMTaskTrace] = []
        fallback_reasons: list[str] = []

        classification, classification_trace = self._run_or_fallback(
            task_name="attack_classification",
            prompt_name="attack_classification.md",
            safe_bundle=safe_bundle,
            validator=validate_classification_response,
            fallback_factory=lambda: self._fallback_classification(bundle),
        )
        task_traces.append(classification_trace)
        if classification_trace.validation_error:
            fallback_reasons.append(classification_trace.validation_error)

        mitre_mapping, mitre_trace = self._run_or_fallback(
            task_name="mitre_mapping",
            prompt_name="mitre_mapping.md",
            safe_bundle=safe_bundle,
            validator=validate_mitre_mapping_response,
            fallback_factory=lambda: self._fallback_mitre_mapping(bundle),
        )
        task_traces.append(mitre_trace)
        if mitre_trace.validation_error:
            fallback_reasons.append(mitre_trace.validation_error)

        narrative, narrative_trace = self._run_or_fallback(
            task_name="analyst_summary",
            prompt_name="analyst_summary.md",
            safe_bundle=safe_bundle,
            validator=validate_narrative_response,
            fallback_factory=lambda: self._fallback_narrative(bundle, provider_mode=self.provider.provider_name),
        )
        task_traces.append(narrative_trace)
        if narrative_trace.validation_error:
            fallback_reasons.append(narrative_trace.validation_error)

        analysis = LLMAnalysisOutput(
            severity=self._deterministic_severity_hint(bundle),
            attack_type=classification.attack_type,
            mitre_techniques=mitre_mapping.mitre_techniques,
            confidence_score=classification.confidence_score,
            analysis_summary=narrative.analysis_summary,
            recommended_actions=narrative.recommended_actions,
        )

        trace = LLMExecutionTrace(
            provider=self.provider.provider_name,
            model=self.provider.model_name,
            prompt_version=settings.llm_prompt_version,
            used_fallback=any(task.used_fallback for task in task_traces),
            fallback_reason=" | ".join(fallback_reasons) if fallback_reasons else None,
            sanitized_bundle=safe_bundle,
            tasks=task_traces,
        )
        return LLMAnalysisResult(analysis=analysis, trace=trace)

    def _run_or_fallback(
        self,
        *,
        task_name: str,
        prompt_name: str,
        safe_bundle: dict[str, Any],
        validator: Callable[[str], TaskModel],
        fallback_factory: Callable[[], TaskModel],
    ) -> tuple[TaskModel, LLMTaskTrace]:
        started = perf_counter()
        prompt = self._render_prompt(prompt_name, safe_bundle)
        try:
            if self.provider is None:
                raise LLMProviderError("No LLM provider configured.")

            raw_output = self._run_provider_task(
                task_name=task_name,
                prompt=prompt,
                safe_bundle=safe_bundle,
            )
            result = validator(raw_output)
            duration = perf_counter() - started
            metrics_registry.observe(
                "llm_task_runtime_seconds",
                duration,
                labels={"task_name": task_name, "status": "validated", "provider": self.provider.provider_name},
            )
            return result, LLMTaskTrace(
                task_name=task_name,
                prompt_name=prompt_name,
                raw_response=raw_output,
                used_fallback=False,
            )
        except (LLMProviderError, LLMValidationError, ValueError) as exc:
            duration = perf_counter() - started
            provider_name = self.provider.provider_name if self.provider is not None else "deterministic"
            metrics_registry.observe(
                "llm_task_runtime_seconds",
                duration,
                labels={"task_name": task_name, "status": "fallback", "provider": provider_name},
            )
            metrics_registry.increment("llm_fallback_total", labels={"task_name": task_name, "provider": provider_name})
            if isinstance(exc, LLMValidationError):
                metrics_registry.increment(
                    "invalid_llm_responses_total",
                    labels={"task_name": task_name, "provider": provider_name},
                )
            log_event(
                logger,
                30,
                "llm_task_fallback",
                task_name=task_name,
                prompt_name=prompt_name,
                provider=provider_name,
                error=str(exc),
                duration_seconds=round(duration, 4),
            )
            return fallback_factory(), LLMTaskTrace(
                task_name=task_name,
                prompt_name=prompt_name,
                raw_response=None,
                used_fallback=True,
                validation_error=str(exc),
            )

    def _run_provider_task(self, *, task_name: str, prompt: str, safe_bundle: dict[str, Any]) -> str:
        if self.provider is None:
            raise LLMProviderError("No LLM provider configured.")

        if hasattr(self.provider, "complete_task"):
            return self.provider.complete_task(task_name=task_name, prompt=prompt, safe_bundle=safe_bundle)

        # Backward-compatible test double support from the earlier Ollama-only implementation.
        if task_name == "attack_classification" and hasattr(self.provider, "classify_attack"):
            _result, raw_output = self.provider.classify_attack(safe_bundle)
            return raw_output
        if task_name == "mitre_mapping" and hasattr(self.provider, "map_mitre"):
            _result, raw_output = self.provider.map_mitre(safe_bundle)
            return raw_output
        if task_name == "analyst_summary" and hasattr(self.provider, "summarize_for_analyst"):
            _result, raw_output = self.provider.summarize_for_analyst(safe_bundle)
            return raw_output

        raise LLMProviderError(f"Provider does not support task '{task_name}'.")

    def _deterministic_only_result(self, bundle: IncidentBundle, safe_bundle: dict[str, Any]) -> LLMAnalysisResult:
        classification = self._fallback_classification(bundle)
        mitre_mapping = self._fallback_mitre_mapping(bundle)
        narrative = self._fallback_narrative(bundle, provider_mode="deterministic")
        analysis = LLMAnalysisOutput(
            severity=self._deterministic_severity_hint(bundle),
            attack_type=classification.attack_type,
            mitre_techniques=mitre_mapping.mitre_techniques,
            confidence_score=classification.confidence_score,
            analysis_summary=narrative.analysis_summary,
            recommended_actions=narrative.recommended_actions,
        )
        trace = LLMExecutionTrace(
            provider="deterministic",
            model="deterministic-fallback",
            prompt_version=settings.llm_prompt_version,
            used_fallback=True,
            fallback_reason="Deterministic-only mode is configured; AI enrichment provider execution was skipped.",
            sanitized_bundle=safe_bundle,
            tasks=[],
        )
        return LLMAnalysisResult(analysis=analysis, trace=trace)

    def _deterministic_severity_hint(self, bundle: IncidentBundle) -> str:
        if bundle.detection_summary.get("port_scanning_pattern", 0) > 0 and bundle.detection_summary.get(
            "multiple_failed_logins", 0
        ) > 0:
            return "Critical"
        if bundle.detection_summary.get("privilege_escalation", 0) > 0:
            return "High"
        if len(bundle.suspicious_events) >= 3:
            return "Medium"
        return "Low"

    def _fallback_classification(self, bundle: IncidentBundle) -> LLMClassificationOutput:
        if bundle.detection_summary.get("privilege_escalation", 0) > 0:
            attack_type = "Privilege Escalation Attempt"
        elif bundle.detection_summary.get("multiple_failed_logins", 0) > 0:
            attack_type = "Credential Access Attempt"
        elif bundle.detection_summary.get("port_scanning_pattern", 0) > 0:
            attack_type = "Reconnaissance Activity"
        else:
            attack_type = "Suspicious Authentication Activity"

        confidence = min(85, 40 + len(bundle.suspicious_events) * 5)
        return LLMClassificationOutput(attack_type=attack_type, confidence_score=confidence)

    def _fallback_mitre_mapping(self, bundle: IncidentBundle) -> LLMMitreMappingOutput:
        rules = [event.rule_name for event in bundle.suspicious_events]
        mapped = map_rules_to_mitre(rules) or ["T1595"]
        return LLMMitreMappingOutput(mitre_techniques=mapped)

    def _fallback_narrative(self, bundle: IncidentBundle, *, provider_mode: str) -> LLMNarrativeOutput:
        if provider_mode == "deterministic":
            summary_prefix = "Deterministic-only mode is active."
        else:
            summary_prefix = "Provider fallback was used because one or more AI task responses were unavailable or invalid."

        return LLMNarrativeOutput(
            analysis_summary=(
                f"{summary_prefix} Deterministic detections indicate suspicious multi-event activity "
                "that should be triaged by an analyst."
            ),
            recommended_actions=[
                "Confirm source IP exposure and apply temporary containment where appropriate.",
                "Review correlated authentication and endpoint activity for affected accounts or assets.",
                "Preserve relevant telemetry and escalate if privilege misuse or broader lateral activity is confirmed.",
            ],
        )
