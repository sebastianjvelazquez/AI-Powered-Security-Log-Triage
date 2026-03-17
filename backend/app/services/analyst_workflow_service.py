from __future__ import annotations

from time import perf_counter

from app.models.enums import AnalystDisposition, AuditActorType, IncidentStatus
from app.models.schemas import AnalystReviewCreateRequest, IncidentStatusUpdateRequest
from app.observability.logging import get_logger, log_event
from app.observability.metrics import metrics_registry
from app.repositories.incident_repository import IncidentRepository
from app.services.incident_service import IncidentService
from sqlalchemy.orm import Session

logger = get_logger(__name__)


ALLOWED_STATUS_TRANSITIONS: dict[str, set[str]] = {
    IncidentStatus.NEW.value: {
        IncidentStatus.IN_REVIEW.value,
        IncidentStatus.ESCALATED.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.FALSE_POSITIVE.value,
    },
    IncidentStatus.IN_REVIEW.value: {
        IncidentStatus.ESCALATED.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.FALSE_POSITIVE.value,
    },
    IncidentStatus.ESCALATED.value: {
        IncidentStatus.IN_REVIEW.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.FALSE_POSITIVE.value,
    },
    IncidentStatus.CLOSED.value: {
        IncidentStatus.IN_REVIEW.value,
    },
    IncidentStatus.FALSE_POSITIVE.value: {
        IncidentStatus.IN_REVIEW.value,
    },
}


def _derive_status_from_disposition(disposition: str) -> str:
    mapping = {
        AnalystDisposition.TRUE_POSITIVE.value: IncidentStatus.IN_REVIEW.value,
        AnalystDisposition.FALSE_POSITIVE.value: IncidentStatus.FALSE_POSITIVE.value,
        AnalystDisposition.BENIGN.value: IncidentStatus.CLOSED.value,
        AnalystDisposition.NEEDS_REVIEW.value: IncidentStatus.IN_REVIEW.value,
        AnalystDisposition.ESCALATED.value: IncidentStatus.ESCALATED.value,
    }
    return mapping[disposition]


class InvalidIncidentTransitionError(ValueError):
    """Raised when an analyst attempts an invalid workflow transition."""


class AnalystWorkflowService:
    def __init__(
        self,
        repository: IncidentRepository | None = None,
        incident_service: IncidentService | None = None,
    ) -> None:
        self.repository = repository or IncidentRepository()
        self.incident_service = incident_service or IncidentService(repository=self.repository)

    def submit_review(
        self,
        db: Session,
        *,
        incident_id: int,
        review_request: AnalystReviewCreateRequest,
    ):
        started = perf_counter()
        incident = self.repository.get_incident_by_id(db, incident_id=incident_id)
        if incident is None:
            return None

        target_status = review_request.target_status or _derive_status_from_disposition(review_request.disposition)
        self._validate_transition(current_status=incident.status, target_status=target_status)

        previous_status = incident.status
        previous_severity = incident.severity
        review = self.repository.create_analyst_review(
            db,
            incident=incident,
            reviewer=review_request.reviewer,
            disposition=review_request.disposition,
            notes=review_request.notes,
            override_severity=review_request.override_severity,
            override_mitre_techniques=review_request.override_mitre_techniques,
            override_recommended_actions=review_request.override_recommended_actions,
        )
        updated_severity = review_request.override_severity or incident.severity
        self.repository.update_incident_workflow(
            db,
            incident=incident,
            status=target_status,
            severity=updated_severity,
        )

        self.repository.add_audit_log(
            db,
            action="incident.review_submitted",
            entity_type="analyst_review",
            entity_id=str(review.id),
            incident_id=incident.id,
            upload_id=incident.upload_id,
            actor=review_request.reviewer,
            actor_type=AuditActorType.ANALYST.value,
            details={
                "disposition": review_request.disposition,
                "notes_present": bool(review_request.notes),
                "override_severity": review_request.override_severity,
                "override_mitre_techniques": review_request.override_mitre_techniques or [],
                "override_recommended_actions": review_request.override_recommended_actions or [],
            },
        )

        if previous_status != target_status:
            self.repository.add_audit_log(
                db,
                action="incident.status_changed",
                entity_type="incident",
                entity_id=str(incident.id),
                incident_id=incident.id,
                upload_id=incident.upload_id,
                actor=review_request.reviewer,
                actor_type=AuditActorType.ANALYST.value,
                details={
                    "from_status": previous_status,
                    "to_status": target_status,
                    "trigger": "review_submission",
                },
            )

        if review_request.override_severity and review_request.override_severity != previous_severity:
            self.repository.add_audit_log(
                db,
                action="incident.severity_overridden",
                entity_type="incident",
                entity_id=str(incident.id),
                incident_id=incident.id,
                upload_id=incident.upload_id,
                actor=review_request.reviewer,
                actor_type=AuditActorType.ANALYST.value,
                details={
                    "from_severity": previous_severity,
                    "to_severity": review_request.override_severity,
                },
            )

        if review_request.override_mitre_techniques or review_request.override_recommended_actions:
            self.repository.add_audit_log(
                db,
                action="incident.analysis_overridden",
                entity_type="incident",
                entity_id=str(incident.id),
                incident_id=incident.id,
                upload_id=incident.upload_id,
                actor=review_request.reviewer,
                actor_type=AuditActorType.ANALYST.value,
                details={
                    "override_mitre_techniques": review_request.override_mitre_techniques or [],
                    "override_recommended_actions": review_request.override_recommended_actions or [],
                },
            )

        db.commit()
        duration = perf_counter() - started
        metrics_registry.increment("review_counts_total", labels={"disposition": review_request.disposition})
        metrics_registry.observe("review_runtime_seconds", duration, labels={"action": "submit_review"})
        if incident.upload and incident.upload.uploaded_at and review.created_at:
            review_latency_minutes = (review.created_at - incident.upload.uploaded_at).total_seconds() / 60
            metrics_registry.observe("review_time_minutes", review_latency_minutes, labels={"disposition": review_request.disposition})
        log_event(
            logger,
            20,
            "incident_review_submitted",
            incident_id=incident.id,
            reviewer=review_request.reviewer,
            disposition=review_request.disposition,
            target_status=target_status,
            duration_seconds=round(duration, 4),
        )
        return self.incident_service.get_incident_detail_by_id(db, incident_id=incident.id)

    def update_status(
        self,
        db: Session,
        *,
        incident_id: int,
        status_request: IncidentStatusUpdateRequest,
    ):
        started = perf_counter()
        incident = self.repository.get_incident_by_id(db, incident_id=incident_id)
        if incident is None:
            return None

        self._validate_transition(current_status=incident.status, target_status=status_request.status)
        previous_status = incident.status
        self.repository.update_incident_workflow(
            db,
            incident=incident,
            status=status_request.status,
        )
        self.repository.add_audit_log(
            db,
            action="incident.status_changed",
            entity_type="incident",
            entity_id=str(incident.id),
            incident_id=incident.id,
            upload_id=incident.upload_id,
            actor=status_request.reviewer,
            actor_type=AuditActorType.ANALYST.value,
            details={
                "from_status": previous_status,
                "to_status": status_request.status,
                "notes": status_request.notes,
                "trigger": "status_update",
            },
        )
        db.commit()
        duration = perf_counter() - started
        metrics_registry.observe("review_runtime_seconds", duration, labels={"action": "update_status"})
        log_event(
            logger,
            20,
            "incident_status_updated",
            incident_id=incident.id,
            reviewer=status_request.reviewer,
            from_status=previous_status,
            to_status=status_request.status,
            duration_seconds=round(duration, 4),
        )
        return self.incident_service.get_incident_detail_by_id(db, incident_id=incident.id)

    def _validate_transition(self, *, current_status: str, target_status: str) -> None:
        if current_status == target_status:
            return
        allowed = ALLOWED_STATUS_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            raise InvalidIncidentTransitionError(
                f"Invalid incident status transition from '{current_status}' to '{target_status}'."
            )
