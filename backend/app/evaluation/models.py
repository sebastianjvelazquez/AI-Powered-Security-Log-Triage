from datetime import datetime

from pydantic import BaseModel, Field


class BenchmarkCaseDefinition(BaseModel):
    scenario_id: str
    expected_severity: str
    benign_expected: bool = False


class BenchmarkDataset(BaseModel):
    dataset_id: str
    name: str
    description: str
    cases: list[BenchmarkCaseDefinition]


class BenchmarkCaseResult(BaseModel):
    scenario_id: str
    scenario_name: str
    processing_time_ms: float
    total_lines: int
    normalized_events: int
    parser_success_rate: float
    expected_incident_count: int
    actual_incident_count: int
    expected_correlated_incident_count: int
    actual_correlated_incident_count: int
    expected_rule_hits: list[str] = Field(default_factory=list)
    actual_rule_hits: list[str] = Field(default_factory=list)
    expected_mitre_techniques: list[str] = Field(default_factory=list)
    actual_mitre_techniques: list[str] = Field(default_factory=list)
    expected_severity: str
    actual_severity: str
    severity_match: bool
    matched_rule_hits: int
    matched_mitre_hits: int
    llm_valid_schema_count: int
    llm_fallback_count: int
    average_review_time_minutes: float | None = None


class BenchmarkSummary(BaseModel):
    total_cases: int
    parser_success_rate: float
    detection_precision: float
    detection_recall: float
    false_positive_rate: float
    severity_agreement: float
    mitre_mapping_quality: float
    llm_valid_schema_rate: float
    llm_fallback_rate: float
    average_processing_time_ms: float
    average_review_time_minutes: float | None = None


class BenchmarkReport(BaseModel):
    generated_at: datetime
    dataset_id: str
    dataset_name: str
    summary: BenchmarkSummary
    cases: list[BenchmarkCaseResult]
