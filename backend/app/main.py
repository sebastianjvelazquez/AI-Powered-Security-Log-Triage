from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth_routes import router as auth_router
from app.api.job_routes import router as job_router
from app.api.observability_routes import router as observability_router
from app.api.routes import router as incident_router
from app.api.scenario_routes import router as scenario_router
from app.api.system_routes import router as system_router
from app.api.workflow_routes import router as workflow_router
from app.core.config import get_settings
from app.core.database import init_db
from app.core.startup import validate_startup_configuration
from app.observability.logging import configure_logging

settings = get_settings()
configure_logging(settings.log_level)

app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(incident_router, prefix=settings.api_v1_prefix)
app.include_router(auth_router, prefix=settings.api_v1_prefix)
app.include_router(job_router, prefix=settings.api_v1_prefix)
app.include_router(scenario_router, prefix=settings.api_v1_prefix)
app.include_router(system_router, prefix=settings.api_v1_prefix)
app.include_router(workflow_router, prefix=settings.api_v1_prefix)
app.include_router(observability_router)


@app.on_event("startup")
def on_startup() -> None:
    validate_startup_configuration(settings)
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
