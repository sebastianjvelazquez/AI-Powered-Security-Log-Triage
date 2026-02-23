import json
from pathlib import Path

import requests

from app.core.config import get_settings
from app.llm.validator import LLMValidationError, validate_llm_response
from app.models.schemas import IncidentBundle, LLMAnalysisOutput
from app.utils.mitre import map_rules_to_mitre

settings = get_settings()

PROMPT_TEMPLATE_PATH = Path(__file__).with_name("prompt_template.md")


class OllamaClient:
    def __init__(self) -> None:
        self.base_url = settings.ollama_base_url.rstrip("/")
        self.model = settings.ollama_model
        self.timeout = settings.ollama_timeout_seconds

    def _load_prompt_template(self) -> str:
        return PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8")

    def _sanitize_bundle_for_prompt(self, bundle: IncidentBundle) -> dict:
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

    def analyze(self, bundle: IncidentBundle) -> LLMAnalysisOutput:
        prompt_template = self._load_prompt_template()
        safe_bundle = self._sanitize_bundle_for_prompt(bundle)
        prompt = prompt_template.format(incident_bundle_json=json.dumps(safe_bundle, separators=(",", ":")))

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
            },
        }

        response = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        raw_output = data.get("response", "")

        return validate_llm_response(raw_output)


class ResilientLLMAnalyzer:
    def __init__(self) -> None:
        self.client = OllamaClient()

    def analyze_with_fallback(self, bundle: IncidentBundle) -> LLMAnalysisOutput:
        try:
            return self.client.analyze(bundle)
        except (requests.RequestException, LLMValidationError, ValueError):
            return self._fallback_analysis(bundle)

    def _fallback_analysis(self, bundle: IncidentBundle) -> LLMAnalysisOutput:
        rules = [event.rule_name for event in bundle.suspicious_events]
        mitre = map_rules_to_mitre(rules) or ["T1595"]

        confidence = min(85, 40 + len(bundle.suspicious_events) * 5)
        severity = "Medium"
        if bundle.detection_summary.get("privilege_escalation", 0) > 0:
            severity = "High"
        if bundle.detection_summary.get("port_scanning_pattern", 0) > 0 and bundle.detection_summary.get(
            "multiple_failed_logins", 0
        ) > 0:
            severity = "Critical"

        return LLMAnalysisOutput(
            severity=severity,
            attack_type="Credential Access / Reconnaissance Pattern",
            mitre_techniques=mitre,
            confidence_score=confidence,
            analysis_summary=(
                "Fallback analysis used due to unavailable or invalid LLM response. "
                "Detected rule patterns indicate a likely staged intrusion attempt."
            ),
            recommended_actions=[
                "Block or rate-limit offending source IP addresses at edge controls.",
                "Reset potentially targeted accounts and enforce MFA where missing.",
                "Collect endpoint and authentication telemetry for correlated investigation.",
            ],
        )
