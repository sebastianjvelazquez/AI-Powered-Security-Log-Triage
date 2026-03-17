from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.job_routes import router as job_router
from app.api.routes import router as incident_router
from app.api.scenario_routes import router as scenario_router
from app.api.workflow_routes import router as workflow_router
from app.core.config import get_settings
from app.core.database import init_db

settings = get_settings()

app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(incident_router, prefix=settings.api_v1_prefix)
app.include_router(job_router, prefix=settings.api_v1_prefix)
app.include_router(scenario_router, prefix=settings.api_v1_prefix)
app.include_router(workflow_router, prefix=settings.api_v1_prefix)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
