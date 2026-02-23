from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import enforce_size_limit, validate_upload
from app.models.schemas import IncidentDetailResponse, IncidentHistoryItem, UploadResponse
from app.services.incident_service import IncidentService
from app.services.report_service import build_report_json, build_report_markdown

router = APIRouter(prefix="/incidents", tags=["incidents"])
service = IncidentService()


@router.post("/upload", response_model=UploadResponse)
def upload_log_file(source_type: str, file: UploadFile = File(...), db: Session = Depends(get_db)) -> UploadResponse:
    validate_upload(file)
    content = file.file.read()
    enforce_size_limit(content)

    decoded = content.decode("utf-8", errors="replace")
    return service.process_upload(
        db=db,
        filename=file.filename or "unknown.log",
        source_type=source_type,
        content=decoded,
    )


@router.get("/history", response_model=list[IncidentHistoryItem])
def get_incident_history(db: Session = Depends(get_db)) -> list[IncidentHistoryItem]:
    return service.get_history(db)


@router.get("/{upload_id}", response_model=IncidentDetailResponse)
def get_incident(upload_id: int, db: Session = Depends(get_db)) -> IncidentDetailResponse:
    detail = service.get_incident_detail(db, upload_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return detail


@router.get("/{upload_id}/report/json")
def download_report_json(upload_id: int, db: Session = Depends(get_db)) -> JSONResponse:
    detail = service.get_incident_detail(db, upload_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    report = build_report_json(detail)
    return JSONResponse(content=report)


@router.get("/{upload_id}/report/markdown")
def download_report_markdown(upload_id: int, db: Session = Depends(get_db)) -> PlainTextResponse:
    detail = service.get_incident_detail(db, upload_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    report = build_report_markdown(detail)
    return PlainTextResponse(content=report, media_type="text/markdown")
