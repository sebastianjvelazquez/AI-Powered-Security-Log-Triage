from datetime import datetime

import pytest
from fastapi import HTTPException

from app.core.config import Settings
from app.core.rate_limit import RateLimitRule, rate_limiter
from app.core.security import prepare_upload_payload, redact_pii_text, settings as security_settings
from app.core.startup import validate_startup_configuration
from app.services.upload_job_service import UploadJobService
from app.utils.upload_storage import UploadStorage


def test_prepare_upload_payload_rejects_binary_content() -> None:
    with pytest.raises(HTTPException) as exc_info:
        prepare_upload_payload(filename="malware.log", content=b"\x00\x01\x02")

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Binary file content is not supported"


def test_redact_pii_text_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security_settings, "pii_redaction_salt", "unit-test-salt")
    text = "Failed password for invalid user admin@example.com from 203.0.113.4"

    first_redaction, first_count = redact_pii_text(text)
    second_redaction, second_count = redact_pii_text(text)

    assert first_redaction == second_redaction
    assert "admin@example.com" not in first_redaction
    assert "user_redacted_" in first_redaction
    assert first_count == second_count == 2


def test_validate_startup_configuration_rejects_duplicate_tokens() -> None:
    settings = Settings(
        viewer_api_token="shared-token",
        analyst_api_token="shared-token",
        admin_api_token="admin-token",
    )

    with pytest.raises(RuntimeError, match="must be unique"):
        validate_startup_configuration(settings)


def test_validate_startup_configuration_requires_hosted_base_url() -> None:
    settings = Settings(
        llm_provider="hosted",
        hosted_llm_base_url="",
        hosted_llm_endpoint="/v1/triage",
        hosted_llm_response_field="response",
    )

    with pytest.raises(RuntimeError, match="HOSTED_LLM_BASE_URL"):
        validate_startup_configuration(settings)


def test_rate_limiter_blocks_excess_requests() -> None:
    rule = RateLimitRule(action="read", limit=1, window_seconds=60)

    rate_limiter.check(rule=rule, subject="analyst:127.0.0.1")
    with pytest.raises(HTTPException) as exc_info:
        rate_limiter.check(rule=rule, subject="analyst:127.0.0.1")

    assert exc_info.value.status_code == 429


def test_stage_upload_persists_hash_and_retention_metadata(
    db_session,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(security_settings, "enable_pii_redaction", False)
    service = UploadJobService(storage=UploadStorage(str(tmp_path / "uploads")))

    response = service.stage_upload(
        db_session,
        filename="events.log",
        source_type="auth",
        content=b"2026-03-17T01:02:03Z host sshd[10]: Failed password for invalid user admin from 203.0.113.8",
        declared_content_type="text/plain",
    )
    db_session.commit()
    upload = service.incident_repository.get_upload_by_id(db_session, upload_id=response.upload_id)

    assert upload is not None
    assert len(upload.sha256) == 64
    assert upload.mime_type == "text/plain"
    assert upload.pii_redacted is False
    assert upload.retention_expires_at is not None
    assert upload.retention_expires_at > datetime.utcnow()
