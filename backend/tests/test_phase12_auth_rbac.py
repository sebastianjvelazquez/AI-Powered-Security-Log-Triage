from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.auth_routes import router as auth_router
from app.api.job_routes import router as job_router
from app.api.observability_routes import router as observability_router
from app.api.routes import router as incident_router
from app.api.scenario_routes import router as scenario_router
from app.api.workflow_routes import router as workflow_router
from app.core.config import get_settings
from app.core.database import get_db


def create_test_client(db_session) -> TestClient:  # noqa: ANN001
    settings = get_settings()
    app = FastAPI()
    app.include_router(auth_router, prefix=settings.api_v1_prefix)
    app.include_router(incident_router, prefix=settings.api_v1_prefix)
    app.include_router(job_router, prefix=settings.api_v1_prefix)
    app.include_router(scenario_router, prefix=settings.api_v1_prefix)
    app.include_router(workflow_router, prefix=settings.api_v1_prefix)
    app.include_router(observability_router)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_protected_routes_require_bearer_token(db_session) -> None:
    client = create_test_client(db_session)

    response = client.get("/api/v1/incidents/history")

    assert response.status_code == 401
    assert response.json()["detail"] == "Missing bearer token"


def test_viewer_role_can_read_but_cannot_replay_or_access_metrics(db_session) -> None:
    settings = get_settings()
    client = create_test_client(db_session)

    history_response = client.get("/api/v1/incidents/history", headers=_auth_headers(settings.viewer_api_token))
    replay_response = client.post(
        "/api/v1/scenarios/password_spray/replay",
        headers=_auth_headers(settings.viewer_api_token),
    )
    metrics_response = client.get("/metrics", headers=_auth_headers(settings.viewer_api_token))

    assert history_response.status_code == 200
    assert history_response.json() == []
    assert replay_response.status_code == 403
    assert replay_response.json()["detail"] == "Analyst role required"
    assert metrics_response.status_code == 403
    assert metrics_response.json()["detail"] == "Admin role required"


def test_auth_me_and_metrics_allow_expected_roles(db_session) -> None:
    settings = get_settings()
    client = create_test_client(db_session)

    me_response = client.get("/api/v1/auth/me", headers=_auth_headers(settings.analyst_api_token))
    metrics_response = client.get("/metrics", headers=_auth_headers(settings.admin_api_token))

    assert me_response.status_code == 200
    assert me_response.json() == {"username": "analyst", "role": "analyst"}
    assert metrics_response.status_code == 200
    assert "queue_depth" in metrics_response.text
