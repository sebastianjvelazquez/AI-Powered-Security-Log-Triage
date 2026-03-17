from __future__ import annotations

from time import perf_counter

from celery import Task

from app.core.database import SessionLocal
from app.observability.logging import configure_logging, get_logger, log_event
from app.observability.metrics import metrics_registry
from app.models.enums import JobStatus, ProcessingStage
from app.repositories.job_repository import JobRepository
from app.services.processing_pipeline_service import ProcessingPipelineService
from app.tasks.celery_app import celery_app
from app.utils.upload_storage import UploadStorage
from app.core.config import get_settings

settings = get_settings()
configure_logging(settings.log_level)
logger = get_logger(__name__)


@celery_app.task(bind=True, name="app.tasks.pipeline_tasks.process_upload_job")
def process_upload_job(self: Task, job_id: str) -> dict[str, object]:
    db = SessionLocal()
    job_repository = JobRepository()
    pipeline_service = ProcessingPipelineService()
    storage = UploadStorage(settings.upload_storage_dir)
    task_started = perf_counter()

    try:
        job = job_repository.get_by_job_id(db, job_id=job_id)
        if job is None:
            raise ValueError(f"Unknown job_id {job_id}")

        job_repository.attach_celery_task_id(db, job=job, celery_task_id=self.request.id or "")
        content = storage.read_text(job.upload.storage_path or "")

        def transition(stage_name: str) -> None:
            stage = ProcessingStage(stage_name)
            status = JobStatus.COMPLETED if stage == ProcessingStage.COMPLETED else JobStatus.RUNNING
            job_repository.transition(db, job=job, stage=stage, status=status)
            db.commit()

        result = pipeline_service.process_existing_upload(
            db,
            upload=job.upload,
            source_type=job.upload.source_type,
            content=content,
            on_stage_change=transition,
        )
        duration = perf_counter() - task_started
        metrics_registry.observe("task_runtime_seconds", duration, labels={"task_name": "process_upload_job", "status": "completed"})
        log_event(
            logger,
            20,
            "process_upload_job_completed",
            job_id=job.job_id,
            upload_id=result.upload_id,
            incident_id=result.incident_id,
            duration_seconds=round(duration, 4),
        )
        return {"job_id": job.job_id, "upload_id": result.upload_id, "incident_id": result.incident_id}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        job = job_repository.get_by_job_id(db, job_id=job_id)
        if job is not None:
            job_repository.transition(
                db,
                job=job,
                stage=ProcessingStage.FAILED,
                status=JobStatus.FAILED,
                error_message=str(exc),
            )
            db.commit()
        duration = perf_counter() - task_started
        metrics_registry.observe("task_runtime_seconds", duration, labels={"task_name": "process_upload_job", "status": "failed"})
        log_event(
            logger,
            40,
            "process_upload_job_failed",
            job_id=job_id,
            error=str(exc),
            duration_seconds=round(duration, 4),
        )
        raise
    finally:
        db.close()
