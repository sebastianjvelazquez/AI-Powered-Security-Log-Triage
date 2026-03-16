from __future__ import annotations

from celery import Task

from app.core.database import SessionLocal
from app.models.enums import JobStatus, ProcessingStage
from app.repositories.job_repository import JobRepository
from app.services.processing_pipeline_service import ProcessingPipelineService
from app.tasks.celery_app import celery_app
from app.utils.upload_storage import UploadStorage
from app.core.config import get_settings

settings = get_settings()


@celery_app.task(bind=True, name="app.tasks.pipeline_tasks.process_upload_job")
def process_upload_job(self: Task, job_id: str) -> dict[str, object]:
    db = SessionLocal()
    job_repository = JobRepository()
    pipeline_service = ProcessingPipelineService()
    storage = UploadStorage(settings.upload_storage_dir)

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
        raise
    finally:
        db.close()
