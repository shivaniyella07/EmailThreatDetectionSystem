"""Schemas for the manual email analysis endpoint."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ThreatAnalysisRequest(BaseModel):
    """Request schema for manual or pasted email analysis."""

    raw_email: str | None = None
    email_text: str | None = None
    email_body: str | None = None
    body: str | None = None
    text: str | None = None
    headers: dict[str, Any] | list[tuple[str, Any]] | str | None = None
    header: dict[str, Any] | list[tuple[str, Any]] | str | None = None
    subject: str | None = None
    from_email: str | None = None
    sender: str | None = None
    to: str | None = None
    recipient: str | None = None
    email: dict[str, Any] | None = None
    id: str | None = None
    email_id: str | None = None
    enable_external: bool = True


class ThreatAnalysisResponse(BaseModel):
    """Response schema returned to the existing dashboard frontend."""

    analysis_id: str
    email: dict[str, Any]
    overall: dict[str, Any]
    analyses: dict[str, Any]
    top_reasons: list[str] = Field(default_factory=list)
    disclaimer: str
    risk_score: int = 0
    risk_level: str = "SAFE"
    classification: str = "SAFE"
    recommendation: str = ""
    threat_intelligence: dict[str, Any] | None = None

    model_config = ConfigDict(extra="allow")
