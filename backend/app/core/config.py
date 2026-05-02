from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI-Powered Security Log Triage Engine"
    api_v1_prefix: str = "/api/v1"

    database_url: str = "sqlite:///./security_triage.db"
    upload_storage_dir: str = "./data/uploads"

    max_upload_mb: int = 10
    allowed_extensions: str = "log,txt,json,csv"
    allowed_mime_types: str = "text/plain,application/json,text/csv,application/x-ndjson"
    upload_retention_days: int = Field(default=30, ge=1, le=3650)
    enable_pii_redaction: bool = False
    pii_redaction_salt: str = ""

    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    llm_provider: str = "deterministic"
    llm_prompt_version: str = "v3"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    ollama_timeout_seconds: int = 60
    hosted_llm_base_url: str = ""
    hosted_llm_endpoint: str = "/v1/chat/completions"
    hosted_llm_api_style: str = "openai_chat"
    hosted_llm_model: str = "hosted-triage-model"
    hosted_llm_api_key: str = ""
    hosted_llm_api_key_header: str = "Authorization"
    hosted_llm_timeout_seconds: int = 60
    hosted_llm_response_field: str = "response"

    asset_criticality: float = Field(default=1.0, ge=0.5, le=3.0)
    failed_login_threshold: int = 3
    port_scan_threshold: int = 5
    correlation_window_minutes: int = 120
    threat_intel_cache_hours: int = Field(default=24, ge=1, le=168)
    geo_velocity_window_minutes: int = Field(default=60, ge=5, le=720)
    log_level: str = "INFO"
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)
    read_rate_limit: int = Field(default=120, ge=1, le=10000)
    upload_rate_limit: int = Field(default=20, ge=1, le=1000)
    review_rate_limit: int = Field(default=60, ge=1, le=1000)
    viewer_api_token: str = "viewer-dev-token-change-me"
    analyst_api_token: str = "analyst-dev-token-change-me"
    admin_api_token: str = "admin-dev-token-change-me"

    frontend_origin: str = "http://localhost:5173"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

    def allowed_extension_set(self) -> set[str]:
        return {item.strip().lower() for item in self.allowed_extensions.split(",") if item.strip()}

    def allowed_mime_type_set(self) -> set[str]:
        return {item.strip().lower() for item in self.allowed_mime_types.split(",") if item.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
