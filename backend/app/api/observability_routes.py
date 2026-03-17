from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.db_models import ProcessingJob
from app.models.enums import JobStatus
from app.observability.metrics import metrics_registry

router = APIRouter(tags=["observability"])


@router.get("/metrics", response_class=PlainTextResponse)
def get_metrics(db: Session = Depends(get_db)) -> PlainTextResponse:
    queued = db.scalar(select(func.count()).select_from(ProcessingJob).where(ProcessingJob.status == JobStatus.QUEUED.value)) or 0
    running = db.scalar(select(func.count()).select_from(ProcessingJob).where(ProcessingJob.status == JobStatus.RUNNING.value)) or 0
    metrics_registry.set_gauge("queue_depth", float(queued), labels={"status": "queued"})
    metrics_registry.set_gauge("queue_depth", float(running), labels={"status": "running"})
    return PlainTextResponse(metrics_registry.render_prometheus(), media_type="text/plain; version=0.0.4")
