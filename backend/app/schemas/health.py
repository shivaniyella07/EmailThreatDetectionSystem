"""Health-check response contract."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    service: str
