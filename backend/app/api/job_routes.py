from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.database import get_db
from app.core.rate_limit import enforce_rate_limit
from app.models.enums import UserRole
from app.models.schemas import JobStatusResponse
from app.services.upload_job_service import UploadJobService
from app.core.config import get_settings
from app.utils.upload_storage import UploadStorage

settings = get_settings()
router = APIRouter(prefix="/jobs", tags=["jobs"])
upload_job_service = UploadJobService(storage=UploadStorage(settings.upload_storage_dir))


@router.get("/{job_id}", response_model=JobStatusResponse)
def get_job_status(
    job_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_rate_limit("read")),
    __= Depends(require_role(UserRole.VIEWER)),
) -> JobStatusResponse:
    status = upload_job_service.get_job_status(db, job_id=job_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return status


@router.get("/upload/{upload_id}", response_model=JobStatusResponse)
def get_upload_status(
    upload_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_rate_limit("read")),
    __= Depends(require_role(UserRole.VIEWER)),
) -> JobStatusResponse:
    status = upload_job_service.job_repository.get_by_upload_id(db, upload_id=upload_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Job not found for upload")

    incident_id = status.upload.incidents[0].id if status.upload and status.upload.incidents else None
    return JobStatusResponse(
        job_id=status.job_id,
        upload_id=status.upload_id,
        status=status.status,
        current_stage=status.current_stage,
        error_message=status.error_message,
        incident_id=incident_id,
        created_at=status.created_at,
        started_at=status.started_at,
        completed_at=status.completed_at,
    )
