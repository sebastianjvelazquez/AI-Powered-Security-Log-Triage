from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.schemas import AnalystReviewCreateRequest, IncidentDetailResponse, IncidentStatusUpdateRequest
from app.services.analyst_workflow_service import AnalystWorkflowService, InvalidIncidentTransitionError

router = APIRouter(prefix="/incidents", tags=["workflow"])
workflow_service = AnalystWorkflowService()


@router.post("/{incident_id}/reviews", response_model=IncidentDetailResponse)
def submit_incident_review(
    incident_id: int,
    review_request: AnalystReviewCreateRequest,
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    try:
        detail = workflow_service.submit_review(
            db,
            incident_id=incident_id,
            review_request=review_request,
        )
    except InvalidIncidentTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return detail


@router.patch("/{incident_id}/status", response_model=IncidentDetailResponse)
def update_incident_status(
    incident_id: int,
    status_request: IncidentStatusUpdateRequest,
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    try:
        detail = workflow_service.update_status(
            db,
            incident_id=incident_id,
            status_request=status_request,
        )
    except InvalidIncidentTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return detail
