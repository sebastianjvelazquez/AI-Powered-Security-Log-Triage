from __future__ import annotations

from pathlib import Path
from uuid import uuid4


class UploadStorage:
    def __init__(self, base_dir: str) -> None:
        self.base_path = Path(base_dir)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def write(self, *, filename: str, content: bytes) -> str:
        safe_name = filename.replace("/", "_").replace("\\", "_")
        target = self.base_path / f"{uuid4().hex}_{safe_name}"
        target.write_bytes(content)
        return str(target)

    def read_text(self, storage_path: str) -> str:
        return Path(storage_path).read_text(encoding="utf-8", errors="replace")
