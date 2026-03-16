from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import enforce_size_limit, validate_upload
from app.models.schemas import IncidentDetailResponse, IncidentHistoryItem, UploadJobResponse, UploadResponse
from app.repositories.job_repository import JobRepository
from app.services.incident_service import IncidentService
from app.services.report_service import build_report_json, build_report_markdown
from app.services.upload_job_service import UploadJobService
from app.tasks.pipeline_tasks import process_upload_job
from app.utils.upload_storage import UploadStorage

router = APIRouter(prefix="/incidents", tags=["incidents"])
settings = get_settings()
incident_service = IncidentService()
job_repository = JobRepository()
upload_job_service = UploadJobService(storage=UploadStorage(settings.upload_storage_dir))


@router.post("/upload", response_model=UploadJobResponse)
def upload_log_file(source_type: str, file: UploadFile = File(...), db: Session = Depends(get_db)) -> UploadJobResponse:
    validate_upload(file)
    content = file.file.read()
    enforce_size_limit(content)

    job_response = upload_job_service.stage_upload(
        db,
        filename=file.filename or "unknown.log",
        source_type=source_type,
        content=content,
    )
    task_result = process_upload_job.delay(job_response.job_id)
    job = job_repository.get_by_job_id(db, job_id=job_response.job_id)
    if job is not None:
        job_repository.attach_celery_task_id(db, job=job, celery_task_id=task_result.id)
        db.commit()

    return job_response


@router.post("/upload/sync", response_model=UploadResponse)
def upload_log_file_sync(source_type: str, file: UploadFile = File(...), db: Session = Depends(get_db)) -> UploadResponse:
    validate_upload(file)
    content = file.file.read()
    enforce_size_limit(content)

    decoded = content.decode("utf-8", errors="replace")
    return incident_service.process_upload(
        db=db,
        filename=file.filename or "unknown.log",
        source_type=source_type,
        content=decoded,
    )


@router.get("/history", response_model=list[IncidentHistoryItem])
def get_incident_history(db: Session = Depends(get_db)) -> list[IncidentHistoryItem]:
    return incident_service.get_history(db)


@router.get("/{upload_id}", response_model=IncidentDetailResponse)
def get_incident(upload_id: int, db: Session = Depends(get_db)) -> IncidentDetailResponse:
    detail = incident_service.get_incident_detail(db, upload_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return detail


@router.get("/{upload_id}/report/json")
def download_report_json(upload_id: int, db: Session = Depends(get_db)) -> JSONResponse:
    detail = incident_service.get_incident_detail(db, upload_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    report = build_report_json(detail)
    return JSONResponse(content=report)


@router.get("/{upload_id}/report/markdown")
def download_report_markdown(upload_id: int, db: Session = Depends(get_db)) -> PlainTextResponse:
    detail = incident_service.get_incident_detail(db, upload_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    report = build_report_markdown(detail)
    return PlainTextResponse(content=report, media_type="text/markdown")
