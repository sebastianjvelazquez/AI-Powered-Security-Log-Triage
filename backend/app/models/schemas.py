from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")


class NormalizedEvent(BaseModel):
    line_number: int | None = None
    timestamp: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    event_type: str
    status: str | None = None
    raw_message: str


class SuspiciousEventOut(BaseModel):
    timestamp: str | None = None
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


class IncidentScoreBreakdown(BaseModel):
    rule_score: float
    llm_confidence: int
    asset_criticality: float
    suspicious_event_count: int
    detection_summary: dict[str, int]


class IncidentScoreView(BaseModel):
    total_score: float
    severity: str
    scoring_version: str
    breakdown: IncidentScoreBreakdown


class IncidentEnrichmentView(BaseModel):
    enrichment_type: str
    provider: str
    status: str
    summary: str | None = None
    payload: dict[str, Any]
    created_at: datetime


class AnalystReviewView(BaseModel):
    reviewer: str
    disposition: str
    notes: str | None = None
    override_severity: str | None = None
    override_mitre_techniques: list[str] | None = None
    override_recommended_actions: list[str] | None = None
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
    score: IncidentScoreView | None = None
    enrichments: list[IncidentEnrichmentView] = Field(default_factory=list)
    analyst_reviews: list[AnalystReviewView] = Field(default_factory=list)
