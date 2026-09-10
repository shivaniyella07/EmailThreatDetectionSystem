"""FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.api.threat_analysis import router as threat_analysis_router
from app.core.config import settings

app = FastAPI(
    title="Email Threat Detection System",
    description="Defensive platform for phishing detection and email forensic intelligence.",
    version="0.1.0",
)

# Allow the Vite dev server to call the API during local development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.frontend_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix="/api")
app.include_router(threat_analysis_router, prefix="/api")


@app.get("/")
def root() -> dict:
    return {
        "service": settings.app_name,
        "message": "API is running. See /api/health and /docs.",
    }
