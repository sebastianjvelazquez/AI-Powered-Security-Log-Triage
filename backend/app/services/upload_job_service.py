from __future__ import annotations

from time import perf_counter

from sqlalchemy.orm import Session

from app.models.schemas import JobStatusResponse, UploadJobResponse
from app.observability.logging import get_logger, log_event
from app.observability.metrics import metrics_registry
from app.repositories.incident_repository import IncidentRepository
from app.repositories.job_repository import JobRepository
from app.utils.upload_storage import UploadStorage

logger = get_logger(__name__)


class UploadJobService:
    def __init__(
        self,
        *,
        storage: UploadStorage,
        incident_repository: IncidentRepository | None = None,
        job_repository: JobRepository | None = None,
    ) -> None:
        self.storage = storage
        self.incident_repository = incident_repository or IncidentRepository()
        self.job_repository = job_repository or JobRepository()

    def stage_upload(self, db: Session, *, filename: str, source_type: str, content: bytes) -> UploadJobResponse:
        started = perf_counter()
        storage_path = self.storage.write(filename=filename, content=content)
        upload = self.incident_repository.create_upload(
            db,
            filename=filename,
            source_type=source_type,
            total_lines=len(content.decode("utf-8", errors="replace").splitlines()),
            normalized_event_count=0,
            storage_path=storage_path,
            processing_status="uploaded",
        )
        self.incident_repository.add_audit_log(
            db,
            action="upload.staged",
            entity_type="upload",
            entity_id=str(upload.id),
            upload_id=upload.id,
            details={"storage_path": storage_path, "source_type": source_type},
        )
        job = self.job_repository.create_job(db, upload=upload)
        db.commit()
        duration = perf_counter() - started
        metrics_registry.increment("uploads_total", labels={"source_type": source_type})
        metrics_registry.observe("upload_stage_duration_seconds", duration, labels={"source_type": source_type})
        log_event(
            logger,
            20,
            "upload_staged",
            upload_id=upload.id,
            job_id=job.job_id,
            source_type=source_type,
            filename=filename,
            total_lines=upload.total_lines,
            duration_seconds=round(duration, 4),
        )

        return UploadJobResponse(
            upload_id=upload.id,
            job_id=job.job_id,
            status=job.status,
            current_stage=job.current_stage,
        )

    def get_job_status(self, db: Session, *, job_id: str) -> JobStatusResponse | None:
        job = self.job_repository.get_by_job_id(db, job_id=job_id)
        if job is None:
            return None

        incident_id = job.upload.incidents[0].id if job.upload and job.upload.incidents else None
        return JobStatusResponse(
            job_id=job.job_id,
            upload_id=job.upload_id,
            status=job.status,
            current_stage=job.current_stage,
            error_message=job.error_message,
            incident_id=incident_id,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
        )
