from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.db_models import ProcessingJob, Upload
from app.models.enums import JobStatus, ProcessingStage


class JobRepository:
    def create_job(self, db: Session, *, upload: Upload) -> ProcessingJob:
        created_at = datetime.utcnow()
        job = ProcessingJob(
            job_id=uuid4().hex,
            upload_id=upload.id,
            status=JobStatus.QUEUED.value,
            current_stage=ProcessingStage.UPLOADED.value,
            stage_history=[
                {
                    "stage": ProcessingStage.UPLOADED.value,
                    "status": JobStatus.QUEUED.value,
                    "timestamp": created_at.isoformat() + "Z",
                }
            ],
            created_at=created_at,
            updated_at=created_at,
        )
        db.add(job)
        db.flush()
        return job

    def get_by_job_id(self, db: Session, *, job_id: str) -> ProcessingJob | None:
        stmt = (
            select(ProcessingJob)
            .where(ProcessingJob.job_id == job_id)
            .options(joinedload(ProcessingJob.upload).joinedload(Upload.incidents))
        )
        return db.scalars(stmt).unique().one_or_none()

    def get_by_upload_id(self, db: Session, *, upload_id: int) -> ProcessingJob | None:
        stmt = (
            select(ProcessingJob)
            .where(ProcessingJob.upload_id == upload_id)
            .order_by(ProcessingJob.created_at.desc())
            .options(joinedload(ProcessingJob.upload).joinedload(Upload.incidents))
        )
        return db.scalars(stmt).unique().first()

    def attach_celery_task_id(self, db: Session, *, job: ProcessingJob, celery_task_id: str) -> ProcessingJob:
        job.celery_task_id = celery_task_id
        job.updated_at = datetime.utcnow()
        db.flush()
        return job

    def transition(
        self,
        db: Session,
        *,
        job: ProcessingJob,
        stage: ProcessingStage,
        status: JobStatus,
        error_message: str | None = None,
    ) -> ProcessingJob:
        now = datetime.utcnow()
        if job.started_at is None and status == JobStatus.RUNNING:
            job.started_at = now
        if status in {JobStatus.COMPLETED, JobStatus.FAILED}:
            job.completed_at = now

        history = list(job.stage_history)
        history.append(
            {
                "stage": stage.value,
                "status": status.value,
                "timestamp": now.isoformat() + "Z",
            }
        )

        job.status = status.value
        job.current_stage = stage.value
        job.stage_history = history
        job.error_message = error_message
        job.updated_at = now
        job.upload.processing_status = stage.value
        job.upload.last_error = error_message
        db.flush()
        return job
