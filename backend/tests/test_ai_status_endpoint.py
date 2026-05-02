from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.system_routes import router as system_router
from app.core.config import get_settings


def test_ai_status_endpoint_reports_deterministic_mode() -> None:
    settings = get_settings()
    app = FastAPI()
    app.include_router(system_router, prefix=settings.api_v1_prefix)
    client = TestClient(app)

    response = client.get(
        "/api/v1/system/ai-status",
        headers={"Authorization": f"Bearer {settings.viewer_api_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == settings.llm_provider
    assert body["deterministic_fallback_available"] is True
    assert body["raw_logs_sent_to_provider"] is False
