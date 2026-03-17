from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")
INCIDENT_STATUS_LEVELS = ("new", "in_review", "escalated", "closed", "false_positive")
ANALYST_DISPOSITIONS = ("true_positive", "false_positive", "benign", "needs_review", "escalated")


class NormalizedEvent(BaseModel):
    line_number: int | None = None
    timestamp: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    event_type: str
    status: str | None = None
    raw_message: str


class SuspiciousEventOut(BaseModel):
    timestamp: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    event_type: str
    status: str | None = None
    rule_name: str
    reason: str
    risk_weight: int = Field(ge=0, le=100)
    raw_message: str


class DetectionCandidate(SuspiciousEventOut):
    normalized_event_index: int = Field(ge=0)


class IncidentBundle(BaseModel):
    source_type: str
    suspicious_events: list[SuspiciousEventOut]
    detection_summary: dict[str, int]


class LLMAnalysisOutput(BaseModel):
    severity: Literal["Low", "Medium", "High", "Critical"]
    attack_type: str = Field(min_length=3, max_length=128)
    mitre_techniques: list[str] = Field(min_length=1)
    confidence_score: int = Field(ge=0, le=100)
    analysis_summary: str = Field(min_length=20, max_length=5000)
    recommended_actions: list[str] = Field(min_length=1)

    @field_validator("mitre_techniques")
    @classmethod
    def validate_mitre_ids(cls, value: list[str]) -> list[str]:
        for technique in value:
            if not technique.startswith("T"):
                raise ValueError("MITRE technique IDs must start with 'T'")
            if not technique[1:].replace(".", "").isdigit():
                raise ValueError("MITRE technique format is invalid")
        return value


class LLMClassificationOutput(BaseModel):
    attack_type: str = Field(min_length=3, max_length=128)
    confidence_score: int = Field(ge=0, le=100)


class LLMMitreMappingOutput(BaseModel):
    mitre_techniques: list[str] = Field(min_length=1)

    @field_validator("mitre_techniques")
    @classmethod
    def validate_mitre_ids(cls, value: list[str]) -> list[str]:
        for technique in value:
            if not technique.startswith("T"):
                raise ValueError("MITRE technique IDs must start with 'T'")
            if not technique[1:].replace(".", "").isdigit():
                raise ValueError("MITRE technique format is invalid")
        return value


class LLMNarrativeOutput(BaseModel):
    analysis_summary: str = Field(min_length=20, max_length=5000)
    recommended_actions: list[str] = Field(min_length=1)


class LLMTaskTrace(BaseModel):
    task_name: str
    prompt_name: str
    raw_response: str | None = None
    used_fallback: bool = False
    validation_error: str | None = None


class LLMExecutionTrace(BaseModel):
    provider: str
    model: str
    prompt_version: str
    used_fallback: bool
    fallback_reason: str | None = None
    sanitized_bundle: dict[str, Any]
    tasks: list[LLMTaskTrace]


class LLMAnalysisResult(BaseModel):
    analysis: LLMAnalysisOutput
    trace: LLMExecutionTrace


class IncidentScoreBreakdown(BaseModel):
    component: str
    score: float
    max_score: float
    rationale: str


class IncidentScoreSummary(BaseModel):
    suspicious_event_count: int
    detection_summary: dict[str, int]
    threat_intel_hits: int
    correlation_strength: int


class IncidentScoreView(BaseModel):
    total_score: float
    severity: str
    scoring_version: str
    breakdown: list[IncidentScoreBreakdown]
    summary: IncidentScoreSummary


class ThreatIntelIndicator(BaseModel):
    indicator: str
    indicator_type: Literal["ip"] = "ip"
    network_scope: str
    is_private: bool
    country: str | None = None
    asn: str | None = None
    reputation_score: float = Field(ge=0, le=100)
    is_malicious: bool = False
    tor_vpn: bool = False
    known_indicator: bool = False
    anomaly_flags: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ThreatIntelEnrichmentSummary(BaseModel):
    indicators_evaluated: int
    public_ip_count: int
    malicious_indicator_count: int
    tor_vpn_count: int
    highest_reputation_score: float = Field(ge=0, le=100)
    anomaly_flags: list[str] = Field(default_factory=list)


class ThreatIntelEnrichmentPayload(BaseModel):
    provider: str
    indicators: list[ThreatIntelIndicator]
    summary: ThreatIntelEnrichmentSummary


class IncidentEnrichmentView(BaseModel):
    enrichment_type: str
    provider: str
    status: str
    summary: str | None = None
    payload: dict[str, Any]
    created_at: datetime


class AnalystReviewView(BaseModel):
    review_id: int | None = None
    reviewer: str
    disposition: str
    notes: str | None = None
    override_severity: str | None = None
    override_mitre_techniques: list[str] | None = None
    override_recommended_actions: list[str] | None = None
    created_at: datetime


class AnalystReviewCreateRequest(BaseModel):
    reviewer: str = Field(min_length=3, max_length=128)
    disposition: Literal["true_positive", "false_positive", "benign", "needs_review", "escalated"]
    notes: str | None = Field(default=None, max_length=5000)
    target_status: Literal["new", "in_review", "escalated", "closed", "false_positive"] | None = None
    override_severity: Literal["Low", "Medium", "High", "Critical"] | None = None
    override_mitre_techniques: list[str] | None = None
    override_recommended_actions: list[str] | None = None

    @field_validator("override_mitre_techniques")
    @classmethod
    def validate_override_mitre_ids(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        for technique in value:
            if not technique.startswith("T"):
                raise ValueError("MITRE technique IDs must start with 'T'")
            if not technique[1:].replace(".", "").isdigit():
                raise ValueError("MITRE technique format is invalid")
        return value


class IncidentStatusUpdateRequest(BaseModel):
    reviewer: str = Field(min_length=3, max_length=128)
    status: Literal["new", "in_review", "escalated", "closed", "false_positive"]
    notes: str | None = Field(default=None, max_length=2000)


class AuditLogView(BaseModel):
    actor: str
    actor_type: str
    action: str
    entity_type: str
    entity_id: str
    details: dict[str, Any] | None = None
    created_at: datetime


class UploadResponse(BaseModel):
    upload_id: int
    incident_id: int
    filename: str
    source_type: str
    title: str
    status: str
    total_lines: int
    suspicious_count: int
    suspicious_events: list[SuspiciousEventOut]
    severity: str
    risk_score: float
    analysis: LLMAnalysisOutput


class UploadJobResponse(BaseModel):
    upload_id: int
    job_id: str
    status: str
    current_stage: str


class JobStatusResponse(BaseModel):
    job_id: str
    upload_id: int
    status: str
    current_stage: str
    error_message: str | None = None
    incident_id: int | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class IncidentHistoryItem(BaseModel):
    incident_id: int
    upload_id: int | None = None
    title: str
    filename: str | None = None
    source_type: str
    status: str
    suspicious_count: int
    severity: str | None = None
    risk_score: float | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    latest_disposition: str | None = None
    uploaded_at: datetime


class IncidentDetailResponse(BaseModel):
    incident_id: int
    upload_id: int | None = None
    filename: str | None = None
    title: str
    status: str
    source_type: str
    total_lines: int
    suspicious_count: int
    uploaded_at: datetime
    suspicious_events: list[SuspiciousEventOut]
    analysis: LLMAnalysisOutput | None = None
    effective_severity: str | None = None
    effective_mitre_techniques: list[str] = Field(default_factory=list)
    effective_recommended_actions: list[str] = Field(default_factory=list)
    latest_disposition: str | None = None
    score: IncidentScoreView | None = None
    correlation_summary: str | None = None
    correlation_context: dict[str, Any] | None = None
    enrichments: list[IncidentEnrichmentView] = Field(default_factory=list)
    analyst_reviews: list[AnalystReviewView] = Field(default_factory=list)
    audit_logs: list[AuditLogView] = Field(default_factory=list)
