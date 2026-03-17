from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.schemas import ReplayJobSummary, ScenarioDetailResponse, ScenarioPack, ScenarioReplayResponse, ScenarioSummaryResponse
from app.services.upload_job_service import UploadJobService


class ScenarioNotFoundError(FileNotFoundError):
    """Raised when a scenario pack cannot be found."""


class ScenarioReplayService:
    def __init__(
        self,
        *,
        upload_job_service: UploadJobService,
        scenario_dir: str | Path | None = None,
    ) -> None:
        self.upload_job_service = upload_job_service
        self.scenario_dir = Path(scenario_dir) if scenario_dir else Path(__file__).resolve().parents[2] / "scenarios"

    def list_scenarios(self) -> list[ScenarioSummaryResponse]:
        scenarios = [self._load_scenario(path) for path in sorted(self.scenario_dir.glob("*.json"))]
        return [
            ScenarioSummaryResponse(
                scenario_id=scenario.scenario_id,
                name=scenario.name,
                description=scenario.description,
                tags=scenario.tags,
                source_types=sorted({upload.source_type for upload in scenario.uploads}),
                upload_count=len(scenario.uploads),
                expected_outcome=scenario.expected_outcome,
            )
            for scenario in scenarios
        ]

    def get_scenario(self, scenario_id: str) -> ScenarioDetailResponse:
        scenario = self._load_scenario(self._path_for_scenario(scenario_id))
        return ScenarioDetailResponse(
            scenario_id=scenario.scenario_id,
            name=scenario.name,
            description=scenario.description,
            tags=scenario.tags,
            source_types=sorted({upload.source_type for upload in scenario.uploads}),
            upload_count=len(scenario.uploads),
            uploads=scenario.uploads,
            expected_outcome=scenario.expected_outcome,
        )

    def replay_scenario(self, db: Session, *, scenario_id: str) -> ScenarioReplayResponse:
        scenario = self._load_scenario(self._path_for_scenario(scenario_id))
        staged_jobs: list[ReplayJobSummary] = []
        for upload in scenario.uploads:
            job = self.upload_job_service.stage_upload(
                db,
                filename=upload.filename,
                source_type=upload.source_type,
                content=upload.content.encode("utf-8"),
            )
            upload_record = self.upload_job_service.incident_repository.get_upload_by_id(db, upload_id=job.upload_id)
            if upload_record is not None:
                self.upload_job_service.incident_repository.add_audit_log(
                    db,
                    action="scenario.replayed",
                    entity_type="upload",
                    entity_id=str(upload_record.id),
                    upload_id=upload_record.id,
                    details={
                        "scenario_id": scenario.scenario_id,
                        "scenario_name": scenario.name,
                        "source_type": upload.source_type,
                    },
                )
            staged_jobs.append(
                ReplayJobSummary(
                    upload_id=job.upload_id,
                    job_id=job.job_id,
                    filename=upload.filename,
                    source_type=upload.source_type,
                    status=job.status,
                    current_stage=job.current_stage,
                )
            )
        db.commit()
        return ScenarioReplayResponse(
            scenario_id=scenario.scenario_id,
            name=scenario.name,
            jobs=staged_jobs,
            expected_outcome=scenario.expected_outcome,
        )

    def _path_for_scenario(self, scenario_id: str) -> Path:
        scenario_path = self.scenario_dir / f"{scenario_id}.json"
        if not scenario_path.exists():
            raise ScenarioNotFoundError(scenario_id)
        return scenario_path

    def _load_scenario(self, path: Path) -> ScenarioPack:
        return ScenarioPack.model_validate(json.loads(path.read_text(encoding="utf-8")))
