from pathlib import Path

from app.models.db_models import AuditLog, ProcessingJob, Upload
from app.services.scenario_replay_service import ScenarioReplayService
from app.services.upload_job_service import UploadJobService
from app.utils.upload_storage import UploadStorage


def test_builtin_scenario_catalog_loads_expected_entries(tmp_path: Path) -> None:
    service = ScenarioReplayService(
        upload_job_service=UploadJobService(storage=UploadStorage(str(tmp_path))),
        scenario_dir=Path(__file__).resolve().parents[1] / "scenarios",
    )

    scenarios = service.list_scenarios()

    scenario_ids = {scenario.scenario_id for scenario in scenarios}
    assert "password_spray" in scenario_ids
    assert "mixed_attack_chain" in scenario_ids
    assert len(scenarios) >= 6


def test_replay_service_stages_multi_upload_scenario(db_session, tmp_path: Path) -> None:
    service = ScenarioReplayService(
        upload_job_service=UploadJobService(storage=UploadStorage(str(tmp_path))),
        scenario_dir=Path(__file__).resolve().parents[1] / "scenarios",
    )

    replay = service.replay_scenario(db_session, scenario_id="recon_auth_abuse")

    assert replay.scenario_id == "recon_auth_abuse"
    assert len(replay.jobs) == 2
    assert replay.expected_outcome.expected_correlated_incident_count == 1

    uploads = db_session.query(Upload).order_by(Upload.id).all()
    jobs = db_session.query(ProcessingJob).order_by(ProcessingJob.id).all()
    audit_logs = db_session.query(AuditLog).filter(AuditLog.action == "scenario.replayed").all()

    assert len(uploads) == 2
    assert len(jobs) == 2
    assert len(audit_logs) == 2
    assert {upload.source_type for upload in uploads} == {"firewall", "auth"}
