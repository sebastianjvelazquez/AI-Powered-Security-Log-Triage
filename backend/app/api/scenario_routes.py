from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import enforce_rate_limit
from app.models.enums import UserRole
from app.models.schemas import ScenarioDetailResponse, ScenarioReplayResponse, ScenarioSummaryResponse
from app.repositories.job_repository import JobRepository
from app.services.scenario_replay_service import ScenarioNotFoundError, ScenarioReplayService
from app.services.upload_job_service import UploadJobService
from app.tasks.pipeline_tasks import process_upload_job
from app.utils.upload_storage import UploadStorage

settings = get_settings()
router = APIRouter(prefix="/scenarios", tags=["scenarios"])
job_repository = JobRepository()
scenario_service = ScenarioReplayService(
    upload_job_service=UploadJobService(storage=UploadStorage(settings.upload_storage_dir)),
)


@router.get("", response_model=list[ScenarioSummaryResponse])
def list_scenarios(
    _: None = Depends(enforce_rate_limit("read")),
    __= Depends(require_role(UserRole.VIEWER)),
) -> list[ScenarioSummaryResponse]:
    return scenario_service.list_scenarios()


@router.get("/{scenario_id}", response_model=ScenarioDetailResponse)
def get_scenario(
    scenario_id: str,
    _: None = Depends(enforce_rate_limit("read")),
    __= Depends(require_role(UserRole.VIEWER)),
) -> ScenarioDetailResponse:
    try:
        return scenario_service.get_scenario(scenario_id)
    except ScenarioNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scenario not found") from exc


@router.post("/{scenario_id}/replay", response_model=ScenarioReplayResponse)
def replay_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(enforce_rate_limit("upload")),
    __= Depends(require_role(UserRole.ANALYST)),
) -> ScenarioReplayResponse:
    try:
        replay_response = scenario_service.replay_scenario(db, scenario_id=scenario_id)
    except ScenarioNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scenario not found") from exc

    for job in replay_response.jobs:
        task_result = process_upload_job.delay(job.job_id)
        persisted_job = job_repository.get_by_job_id(db, job_id=job.job_id)
        if persisted_job is not None:
            job_repository.attach_celery_task_id(db, job=persisted_job, celery_task_id=task_result.id)
    db.commit()
    return replay_response
