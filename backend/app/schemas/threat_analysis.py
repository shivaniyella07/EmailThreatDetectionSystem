"""Pydantic contracts for Member 5 threat intelligence and risk scoring."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class Indicator(BaseModel):
    """A single indicator of compromise or forensic signal."""

    model_config = ConfigDict(extra="allow")

    value: str
    type: str = Field(
        description="Indicator type such as ip, domain, url, email, or auth.",
    )
    source: Optional[str] = None


class ThreatIntelligenceFinding(BaseModel):
    """One local or optional-external intelligence match."""

    model_config = ConfigDict(extra="allow")

    indicator: str
    indicator_type: str
    known: bool = False
    suspicious: bool = False
    threat_category: Optional[str] = None
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    severity: Optional[str] = None
    matching_source: str = "none"
    campaign: Optional[str] = None
    threat_actor: Optional[str] = None
    reason: str = "No match in local threat knowledge."


class CorrelatedIndicator(BaseModel):
    """A multi-indicator pattern that increased risk."""

    pattern: str
    indicators: list[str] = Field(default_factory=list)
    explanation: str
    severity: str = "MEDIUM"


class ThreatIntelligenceResult(BaseModel):
    """Threat-intelligence module payload nested in the analysis response."""

    module: str = "threat_intelligence"
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: str = "SAFE"
    indicators: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    findings: list[ThreatIntelligenceFinding] = Field(default_factory=list)
    unmatched_indicators: list[Indicator] = Field(default_factory=list)


class ThreatAnalysisRequest(BaseModel):
    """Flexible request that accepts existing Member 2/3/4 envelopes.

    Aliases are accepted so Member 1 does not need to reshape prior output.
    Unknown extra fields are ignored at the top level of nested dicts by the
    service layer rather than rejected here.
    """

    model_config = ConfigDict(extra="allow")

    nlp: Optional[Any] = None
    header_analysis: Optional[Any] = None
    header: Optional[Any] = None
    ip_url_analysis: Optional[Any] = None
    url: Optional[Any] = None
    geolocation: Optional[Any] = None
    ip: Optional[Any] = None
    indicators: Optional[Any] = None
    email_text: Optional[str] = None
    email_body: Optional[str] = None
    body: Optional[str] = None
    text: Optional[str] = None
    raw_email: Optional[str] = None
    headers: Optional[Any] = None
    email: Optional[Any] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    from_email: Optional[str] = None
    to: Optional[str] = None
    recipient: Optional[str] = None
    enable_external: bool = True


class RiskResult(BaseModel):
    """Explainable overall risk result."""

    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    classification: str
    reasons: list[str] = Field(default_factory=list)
    recommendation: str
    category_scores: dict[str, int] = Field(default_factory=dict)


class ThreatAnalysisResponse(BaseModel):
    """API response consumed by Member 6 / Member 1 orchestration."""

    model_config = ConfigDict(extra="allow")

    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    classification: str
    reasons: list[str] = Field(default_factory=list)
    recommendation: str
    threat_intelligence: ThreatIntelligenceResult
    correlated_indicators: list[CorrelatedIndicator] = Field(default_factory=list)
    category_scores: dict[str, int] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    email: dict[str, Any] = Field(default_factory=dict)
    overall: dict[str, Any] = Field(default_factory=dict)
    analyses: dict[str, Any] = Field(default_factory=dict)
    top_reasons: list[str] = Field(default_factory=list)
    disclaimer: str = (
        "Analysis provides security intelligence and risk assessment; "
        "it does not prove attacker identity."
    )
