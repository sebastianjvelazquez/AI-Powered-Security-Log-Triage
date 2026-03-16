from pathlib import Path

from app.models.db_models import ProcessingJob, Upload
from app.services.upload_job_service import UploadJobService
from app.utils.upload_storage import UploadStorage


def test_stage_upload_creates_job_and_persists_file(db_session, tmp_path: Path) -> None:
    service = UploadJobService(storage=UploadStorage(str(tmp_path)))
    payload = b"2026-02-22T10:02:13Z host sshd[1245]: Failed password for invalid user admin from 203.0.113.4 port 50123 ssh2"

    response = service.stage_upload(
        db_session,
        filename="auth.log",
        source_type="auth",
        content=payload,
    )

    assert response.upload_id > 0
    assert response.job_id
    assert response.status == "queued"
    assert response.current_stage == "uploaded"

    upload = db_session.get(Upload, response.upload_id)
    assert upload is not None
    assert upload.storage_path is not None
    assert Path(upload.storage_path).exists()

    job = db_session.query(ProcessingJob).filter(ProcessingJob.job_id == response.job_id).one()
    assert job.upload_id == upload.id
    assert job.stage_history[0]["stage"] == "uploaded"
