"""Application settings loaded from environment variables."""

import os

from pydantic import BaseModel, Field


def _split_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


class Settings(BaseModel):
    app_name: str = "EmailThreatDetectionSystem"
    app_env: str = "development"
    frontend_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    )
    gmail_mock_mode: bool = True
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://127.0.0.1:8000/api/gmail/callback"


settings = Settings(
    app_name=os.getenv("APP_NAME", "EmailThreatDetectionSystem"),
    app_env=os.getenv("APP_ENV", "development"),
    frontend_origins=_split_csv(
        os.getenv("FRONTEND_ORIGINS") or os.getenv("FRONTEND_ORIGIN")
    )
    or [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    gmail_mock_mode=os.getenv("GMAIL_MOCK_MODE", "true").strip().lower()
    in {"1", "true", "yes", "on"},
    google_client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    google_client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    google_redirect_uri=os.getenv(
        "GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/api/gmail/callback"
    ),
)
