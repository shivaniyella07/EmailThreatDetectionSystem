"""Application settings loaded from environment variables."""

from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "EmailThreatDetectionSystem"
    app_env: str = "development"


settings = Settings()
