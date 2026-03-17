from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import HTTPException, UploadFile, status

from app.core.config import get_settings

settings = get_settings()

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
USER_PATTERNS = (
    re.compile(r"(?P<prefix>\b(?:user|username|account|accountname|identity)[=:]\s*)(?P<value>[^\s,;]+)", re.IGNORECASE),
    re.compile(r"(?P<prefix>\bfor (?:invalid user )?)(?P<value>[A-Za-z0-9._@-]+)", re.IGNORECASE),
    re.compile(r"(?P<prefix>\b(?:as|by) user\s+)(?P<value>[A-Za-z0-9._@-]+)", re.IGNORECASE),
)


@dataclass(frozen=True)
class PreparedUpload:
    filename: str
    extension: str
    sha256: str
    detected_mime_type: str
    declared_mime_type: str | None
    text_content: str
    storage_content: bytes
    pii_redacted: bool
    redaction_count: int
    retention_expires_at: datetime


def _hash_token(value: str) -> str:
    digest = hashlib.sha256(f"{settings.pii_redaction_salt}:{value}".encode("utf-8")).hexdigest()
    return f"user_redacted_{digest[:12]}"


def redact_pii_text(content: str) -> tuple[str, int]:
    redaction_count = 0

    def replace_email(match: re.Match[str]) -> str:
        nonlocal redaction_count
        redaction_count += 1
        return _hash_token(match.group(0))

    redacted = EMAIL_PATTERN.sub(replace_email, content)

    for pattern in USER_PATTERNS:
        def replace_user(match: re.Match[str]) -> str:
            nonlocal redaction_count
            redaction_count += 1
            return f"{match.group('prefix')}{_hash_token(match.group('value'))}"

        redacted = pattern.sub(replace_user, redacted)

    return redacted, redaction_count


def enforce_size_limit(content: bytes) -> None:
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {settings.max_upload_mb}MB limit",
        )


def _extension_for_filename(filename: str) -> str:
    extension = Path(filename).suffix.lower().replace(".", "")
    if not extension:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Upload is missing a file extension")
    if extension not in settings.allowed_extension_set():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{extension}'. Allowed: {sorted(settings.allowed_extension_set())}",
        )
    return extension


def _decode_text(content: bytes) -> str:
    if b"\x00" in content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Binary file content is not supported")

    text = content.decode("utf-8", errors="replace")
    printable = sum(1 for character in text if character.isprintable() or character in "\n\r\t")
    ratio = printable / max(len(text), 1)
    if ratio < 0.85:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Upload must be UTF-8 text content")
    return text


def _normalize_declared_content_type(content_type: str | None) -> str | None:
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower()


def _is_json_document(content: str) -> bool:
    stripped = content.strip()
    if not stripped:
        return False
    if stripped[0] not in "{[":
        return False
    try:
        json.loads(stripped)
    except json.JSONDecodeError:
        return False
    return True


def _is_ndjson(content: str) -> bool:
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines:
        return False
    sample = lines[:20]
    if not all(line.startswith("{") and line.endswith("}") for line in sample):
        return False
    try:
        for line in sample:
            json.loads(line)
    except json.JSONDecodeError:
        return False
    return True


def _is_csv(content: str) -> bool:
    lines = [line for line in content.splitlines() if line.strip()]
    if len(lines) < 2:
        return False
    sample = "\n".join(lines[:5])
    try:
        dialect = csv.Sniffer().sniff(sample)
    except csv.Error:
        return False
    return dialect.delimiter == ","


def sniff_mime_type(filename: str, content: bytes) -> tuple[str, str]:
    extension = _extension_for_filename(filename)
    text = _decode_text(content)

    if _is_json_document(text):
        return "application/json", text
    if _is_ndjson(text):
        return "application/x-ndjson", text
    if extension == "csv" or _is_csv(text):
        return "text/csv", text
    return "text/plain", text


def prepare_upload_payload(
    *,
    filename: str,
    content: bytes,
    declared_content_type: str | None = None,
) -> PreparedUpload:
    if not filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing filename")

    enforce_size_limit(content)
    extension = _extension_for_filename(filename)
    detected_mime_type, text = sniff_mime_type(filename, content)
    allowed_mime_types = settings.allowed_mime_type_set()

    if detected_mime_type not in allowed_mime_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Detected MIME type '{detected_mime_type}' is not allowed",
        )

    normalized_declared_type = _normalize_declared_content_type(declared_content_type)
    if normalized_declared_type and normalized_declared_type not in {"application/octet-stream", *allowed_mime_types}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Declared MIME type '{normalized_declared_type}' is not allowed",
        )

    storage_text = text
    redaction_count = 0
    pii_redacted = False
    if settings.enable_pii_redaction:
        storage_text, redaction_count = redact_pii_text(text)
        pii_redacted = redaction_count > 0

    return PreparedUpload(
        filename=filename,
        extension=extension,
        sha256=hashlib.sha256(content).hexdigest(),
        detected_mime_type=detected_mime_type,
        declared_mime_type=normalized_declared_type,
        text_content=storage_text,
        storage_content=storage_text.encode("utf-8"),
        pii_redacted=pii_redacted,
        redaction_count=redaction_count,
        retention_expires_at=datetime.utcnow() + timedelta(days=settings.upload_retention_days),
    )


def validate_upload(file: UploadFile, content: bytes) -> PreparedUpload:
    return prepare_upload_payload(
        filename=file.filename or "",
        content=content,
        declared_content_type=file.content_type,
    )
