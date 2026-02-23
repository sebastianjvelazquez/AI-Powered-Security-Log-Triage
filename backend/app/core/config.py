from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI-Powered Security Log Triage Engine"
    api_v1_prefix: str = "/api/v1"

    database_url: str = "sqlite:///./security_triage.db"

    max_upload_mb: int = 10
    allowed_extensions: str = "log,txt,json,csv"

    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    ollama_timeout_seconds: int = 60

    asset_criticality: float = Field(default=1.0, ge=0.5, le=3.0)
    failed_login_threshold: int = 3
    port_scan_threshold: int = 5

    frontend_origin: str = "http://localhost:5173"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)


@lru_cache
def get_settings() -> Settings:
    return Settings()
