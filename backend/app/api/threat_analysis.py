"""Member 5 threat-analysis API.

Member 1 owns ``backend/app/main.py``. Include this router with:

    from app.api.threat_analysis import router as threat_analysis_router
    app.include_router(threat_analysis_router, prefix="/api")
"""

from typing import Any

from fastapi import APIRouter

from app.schemas.threat_analysis import ThreatAnalysisRequest, ThreatAnalysisResponse
from app.services.risk_engine import score_threat

router = APIRouter()


@router.post("/threat-analysis", response_model=ThreatAnalysisResponse)
def post_threat_analysis(body: ThreatAnalysisRequest) -> dict[str, Any]:
    """Score combined findings from Members 2–4 plus local threat intelligence."""
    payload = body.model_dump()
    return score_threat(payload)
