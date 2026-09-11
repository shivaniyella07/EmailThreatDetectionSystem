"""Gmail OAuth, mailbox listing, and selected-email analysis routes."""

from fastapi import APIRouter, HTTPException, Query

from app.api.threat_analysis import post_threat_analysis
from app.schemas.gmail import GmailAuthResponse, GmailCallbackResponse, GmailEmailListResponse
from app.schemas.threat_analysis import ThreatAnalysisRequest, ThreatAnalysisResponse
from app.services.gmail_service import gmail_service

router = APIRouter(prefix="/gmail", tags=["gmail"])


@router.get("/auth", response_model=GmailAuthResponse)
def begin_gmail_auth() -> GmailAuthResponse:
    """Return a Google authorization URL or mock callback URL for development."""
    mode = "mock" if gmail_service.is_mock_mode else "oauth"
    return GmailAuthResponse(
        mode=mode,
        authorization_url=gmail_service.authorization_url(),
        message=("Mock Gmail authorization is ready; no Google credentials are required." if mode == "mock" else "Open authorization_url to grant read-only Gmail access."),
    )


@router.get("/callback", response_model=GmailCallbackResponse)
def gmail_callback(code: str | None = Query(default=None), error: str | None = Query(default=None)) -> GmailCallbackResponse:
    connected, message = gmail_service.complete_callback(code=code, error=error)
    return GmailCallbackResponse(connected=connected, mode="mock" if gmail_service.is_mock_mode else "oauth", message=message)


@router.get("/emails", response_model=GmailEmailListResponse)
def list_gmail_emails() -> GmailEmailListResponse:
    """List recent message metadata without returning bodies or credentials."""
    try:
        emails = gmail_service.list_recent_emails()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return GmailEmailListResponse(mode="mock" if gmail_service.is_mock_mode else "oauth", emails=emails)


@router.post("/analyze/{email_id}", response_model=ThreatAnalysisResponse)
def analyze_gmail_email(email_id: str) -> dict:
    """Fetch a selected message, normalize it, then use the shared analysis pipeline."""
    try:
        email = gmail_service.get_email(email_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if email is None:
        raise HTTPException(status_code=404, detail="Gmail message was not found.")
    return post_threat_analysis(ThreatAnalysisRequest(email={"id": email_id, **email}, email_text=email.get("text", ""), headers=email.get("headers", {})))