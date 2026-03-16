from enum import StrEnum


class IncidentStatus(StrEnum):
    NEW = "new"
    IN_REVIEW = "in_review"
    ESCALATED = "escalated"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class EnrichmentStatus(StrEnum):
    READY = "ready"
    FAILED = "failed"
    PENDING = "pending"


class AuditActorType(StrEnum):
    SYSTEM = "system"
    ANALYST = "analyst"


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    USER = "user"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ProcessingStage(StrEnum):
    UPLOADED = "uploaded"
    PARSING = "parsing"
    DETECTING = "detecting"
    CORRELATING = "correlating"
    ENRICHING = "enriching"
    SCORING = "scoring"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"
