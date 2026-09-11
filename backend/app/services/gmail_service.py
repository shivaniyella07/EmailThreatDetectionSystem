"""Gmail access boundary with a deterministic, credential-free demo mode."""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urlencode

from app.core.config import settings
from app.services.email_parser import parse_email

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

_MOCK_EMAILS: list[dict[str, str]] = [
    {
        "id": "demo-security-alert",
        "from": "Account Security <alerts@example-security.test>",
        "subject": "Action requested: review your account activity",
        "date": "Mon, 08 Sep 2026 10:15:00 +0000",
        "body": "Hello, please review your recent account activity in your usual account portal.",
    },
    {
        "id": "demo-team-update",
        "from": "Project Team <team@example.test>",
        "subject": "Weekly project update",
        "date": "Sun, 07 Sep 2026 09:00:00 +0000",
        "body": "Hi team, the project review is scheduled for Friday at 3 PM.",
    },
]


class GmailService:
    """Provider-neutral Gmail gateway. It never handles Gmail passwords."""

    def __init__(self) -> None:
        self._mock_connected = False

    @property
    def is_mock_mode(self) -> bool:
        return settings.gmail_mock_mode or not settings.google_client_id

    def authorization_url(self) -> str:
        if self.is_mock_mode:
            return f"{settings.google_redirect_uri}?mode=mock"
        query = urlencode({
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": GMAIL_READONLY_SCOPE,
            "access_type": "offline",
            "prompt": "consent",
        })
        return f"https://accounts.google.com/o/oauth2/v2/auth?{query}"

    def complete_callback(self, code: str | None, error: str | None) -> tuple[bool, str]:
        if error:
            return False, f"Gmail authorization was not completed: {error}."
        if self.is_mock_mode:
            self._mock_connected = True
            return True, "Mock Gmail mailbox connected for development."
        if not code:
            return False, "OAuth callback did not include an authorization code."
        return False, "OAuth callback received. Secure token exchange is not configured."

    def list_recent_emails(self) -> list[dict[str, str]]:
        if not self.is_mock_mode:
            raise RuntimeError("Gmail mailbox access is not configured.")
        return [self._summary(message) for message in _MOCK_EMAILS]

    def get_email(self, email_id: str) -> dict[str, Any] | None:
        if not self.is_mock_mode:
            raise RuntimeError("Gmail mailbox access is not configured.")
        for message in _MOCK_EMAILS:
            if message["id"] == email_id:
                return self.normalize_message(message)
        return None

    @staticmethod
    def _summary(message: dict[str, str]) -> dict[str, str]:
        return {"id": message["id"], "from": message["from"], "subject": message["subject"], "date": message["date"], "snippet": message["body"][:160]}

    @staticmethod
    def normalize_message(message: dict[str, Any]) -> dict[str, Any]:
        """Normalize a mock or Gmail API message into the parser's shared shape."""
        if "payload" not in message:
            return parse_email(message)
        headers = {item.get("name", ""): item.get("value", "") for item in message.get("payload", {}).get("headers", []) if item.get("name")}
        body = GmailService._extract_gmail_body(message.get("payload", {}))
        return parse_email({"headers": headers, "subject": headers.get("Subject", ""), "from": headers.get("From", ""), "to": headers.get("To", ""), "body": body})

    @staticmethod
    def _extract_gmail_body(payload: dict[str, Any]) -> str:
        data = (payload.get("body") or {}).get("data")
        if data:
            return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="replace")
        for part in payload.get("parts", []):
            body = GmailService._extract_gmail_body(part)
            if body:
                return body
        return ""


gmail_service = GmailService()