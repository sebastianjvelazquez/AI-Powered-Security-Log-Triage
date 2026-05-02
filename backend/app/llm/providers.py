from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import requests

from app.core.config import get_settings

settings = get_settings()


class LLMProviderError(RuntimeError):
    """Raised when an LLM provider cannot fulfill a task."""


class LLMProvider(ABC):
    provider_name: str
    model_name: str

    @abstractmethod
    def complete_task(self, *, task_name: str, prompt: str, safe_bundle: dict[str, Any]) -> str:
        raise NotImplementedError


class OllamaProvider(LLMProvider):
    provider_name = "ollama"

    def __init__(self) -> None:
        self.base_url = settings.ollama_base_url.rstrip("/")
        self.model_name = settings.ollama_model
        self.timeout = settings.ollama_timeout_seconds

    def complete_task(self, *, task_name: str, prompt: str, safe_bundle: dict[str, Any]) -> str:
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.0, "top_p": 0.9},
        }

        try:
            response = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise LLMProviderError(f"Ollama request failed for task '{task_name}': {exc}") from exc

        data = response.json()
        return str(data.get("response", ""))


class HostedProvider(LLMProvider):
    provider_name = "hosted"

    def __init__(self) -> None:
        self.base_url = settings.hosted_llm_base_url.rstrip("/")
        self.endpoint = settings.hosted_llm_endpoint
        self.api_style = settings.hosted_llm_api_style.strip().lower()
        self.model_name = settings.hosted_llm_model
        self.timeout = settings.hosted_llm_timeout_seconds
        self.api_key = settings.hosted_llm_api_key
        self.api_key_header = settings.hosted_llm_api_key_header
        self.response_field = settings.hosted_llm_response_field

    def _build_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if not self.api_key:
            return headers

        if self.api_key_header.lower() == "authorization":
            headers[self.api_key_header] = f"Bearer {self.api_key}"
        else:
            headers[self.api_key_header] = self.api_key
        return headers

    def complete_task(self, *, task_name: str, prompt: str, safe_bundle: dict[str, Any]) -> str:
        payload = self._build_payload(task_name=task_name, prompt=prompt, safe_bundle=safe_bundle)

        try:
            response = requests.post(
                f"{self.base_url}{self.endpoint}",
                json=payload,
                headers=self._build_headers(),
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise LLMProviderError(f"Hosted provider request failed for task '{task_name}': {exc}") from exc

        return self._extract_response_text(response.json(), task_name=task_name)

    def _build_payload(self, *, task_name: str, prompt: str, safe_bundle: dict[str, Any]) -> dict[str, Any]:
        if self.api_style == "openai_chat":
            return {
                "model": self.model_name,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a SOC enrichment assistant. Return only strict JSON matching the requested schema. "
                            "Do not infer from raw logs; use only the sanitized incident bundle in the prompt."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "metadata": {
                    "task": task_name,
                    "safe_bundle_event_count": len(safe_bundle.get("suspicious_events", [])),
                },
            }

        payload = {
            "model": self.model_name,
            "task": task_name,
            "prompt": prompt,
            "response_format": "json",
            "metadata": {
                "safe_bundle": safe_bundle,
                "provider_mode": "hosted",
            },
        }
        return payload

    def _extract_response_text(self, body: dict[str, Any], *, task_name: str) -> str:
        if self.api_style == "openai_chat":
            try:
                raw_output = body["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError) as exc:
                raise LLMProviderError(
                    f"Hosted chat response for task '{task_name}' did not contain choices[0].message.content."
                ) from exc
            return str(raw_output)

        raw_output = body.get(self.response_field)
        if raw_output is None:
            raise LLMProviderError(
                f"Hosted provider response for task '{task_name}' did not contain field '{self.response_field}'."
            )
        if isinstance(raw_output, (dict, list)):
            return json.dumps(raw_output)
        return str(raw_output)


class MockProvider(LLMProvider):
    provider_name = "mock"

    def __init__(self) -> None:
        self.model_name = "mock-triage-provider"

    def complete_task(self, *, task_name: str, prompt: str, safe_bundle: dict[str, Any]) -> str:
        detection_summary = safe_bundle.get("detection_summary", {})
        suspicious_events = safe_bundle.get("suspicious_events", [])

        if task_name == "attack_classification":
            attack_type = "Suspicious Authentication Activity"
            if detection_summary.get("privilege_escalation", 0) > 0:
                attack_type = "Privilege Escalation Attempt"
            elif detection_summary.get("multiple_failed_logins", 0) > 0:
                attack_type = "Credential Access Attempt"
            elif detection_summary.get("port_scanning_pattern", 0) > 0:
                attack_type = "Reconnaissance Activity"

            return json.dumps(
                {
                    "attack_type": attack_type,
                    "confidence_score": min(90, 45 + len(suspicious_events) * 6),
                }
            )

        if task_name == "mitre_mapping":
            rules = [event.get("rule_name", "") for event in suspicious_events]
            mitre = ["T1595"]
            if "multiple_failed_logins" in rules:
                mitre = ["T1110"]
            elif "privilege_escalation" in rules:
                mitre = ["T1068"]
            return json.dumps({"mitre_techniques": mitre})

        return json.dumps(
            {
                "analysis_summary": (
                    "Mock provider generated an analyst summary from the sanitized incident bundle. "
                    "Deterministic detections still remain the source of truth for prioritization."
                ),
                "recommended_actions": [
                    "Validate the detection chain against source telemetry.",
                    "Contain affected accounts or hosts if malicious behavior is confirmed.",
                ],
            }
        )
