from app.models.db_models import Incident, ProcessingJob, Upload
from app.models.enums import JobStatus, ProcessingStage
from app.repositories.incident_repository import IncidentRepository
from app.repositories.job_repository import JobRepository
from app.models.schemas import LLMAnalysisOutput
from app.services.processing_pipeline_service import ProcessingPipelineService


class StubAnalyzer:
    def analyze_with_fallback(self, bundle):  # noqa: ANN001
        return LLMAnalysisOutput(
            severity="High",
            attack_type="Credential Access",
            mitre_techniques=["T1110"],
            confidence_score=90,
            analysis_summary="Repeated failed logins from a suspicious IP indicate likely credential access activity.",
            recommended_actions=["Block the source IP.", "Reset targeted credentials."],
        )


def test_processing_pipeline_runs_stage_sequence_for_existing_upload(db_session) -> None:
    incident_repository = IncidentRepository()
    upload = incident_repository.create_upload(
        db_session,
        filename="auth.log",
        source_type="auth",
        total_lines=3,
        normalized_event_count=0,
        processing_status="uploaded",
    )
    job_repository = JobRepository()
    job = job_repository.create_job(db_session, upload=upload)
    db_session.commit()

    observed_stages: list[str] = []
    service = ProcessingPipelineService(llm_analyzer=StubAnalyzer(), repository=incident_repository)
    content = "\n".join(
        [
            "2026-02-22T10:02:13Z host sshd[1245]: Failed password for invalid user admin from 203.0.113.4 port 50123 ssh2",
            "2026-02-22T10:02:14Z host sshd[1246]: Failed password for invalid user admin from 203.0.113.4 port 50124 ssh2",
            "2026-02-22T10:02:15Z host sshd[1247]: Failed password for invalid user admin from 203.0.113.4 port 50125 ssh2",
        ]
    )

    def on_stage_change(stage: str) -> None:
        observed_stages.append(stage)
        persisted_job = job_repository.get_by_job_id(db_session, job_id=job.job_id)
        assert persisted_job is not None
        status = JobStatus.COMPLETED if stage == ProcessingStage.COMPLETED.value else JobStatus.RUNNING
        job_repository.transition(db_session, job=persisted_job, stage=ProcessingStage(stage), status=status)
        db_session.commit()

    response = service.process_existing_upload(
        db_session,
        upload=upload,
        source_type="auth",
        content=content,
        on_stage_change=on_stage_change,
    )

    assert response.incident_id > 0
    assert observed_stages == [
        "parsing",
        "detecting",
        "correlating",
        "enriching",
        "scoring",
        "report_generation",
        "completed",
    ]

    persisted_upload = db_session.get(Upload, upload.id)
    assert persisted_upload is not None
    assert persisted_upload.processing_status == "completed"
    assert db_session.query(Incident).count() == 1

    persisted_job = db_session.query(ProcessingJob).filter(ProcessingJob.job_id == job.job_id).one()
    assert persisted_job.status == "completed"
    assert persisted_job.current_stage == "completed"
