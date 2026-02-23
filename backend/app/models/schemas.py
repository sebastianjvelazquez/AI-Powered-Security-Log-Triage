from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")


class NormalizedEvent(BaseModel):
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


class UploadResponse(BaseModel):
    upload_id: int
    filename: str
    source_type: str
    total_lines: int
    suspicious_count: int
    suspicious_events: list[SuspiciousEventOut]
    severity: str
    risk_score: float
    analysis: LLMAnalysisOutput


class IncidentHistoryItem(BaseModel):
    upload_id: int
    filename: str
    source_type: str
    suspicious_count: int
    severity: str | None = None
    risk_score: float | None = None
    uploaded_at: datetime


class IncidentDetailResponse(BaseModel):
    upload_id: int
    filename: str
    source_type: str
    total_lines: int
    suspicious_count: int
    uploaded_at: datetime
    suspicious_events: list[SuspiciousEventOut]
    analysis: LLMAnalysisOutput | None = None
    risk_score: float | None = None
