"""Health endpoint used by the dashboard to check backend connectivity."""

from fastapi import APIRouter

from app.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        service="EmailThreatDetectionSystem",
    )
