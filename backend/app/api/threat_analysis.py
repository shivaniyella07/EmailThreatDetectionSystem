"""Member 1 orchestration API for manual email analysis."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.schemas.threat_analysis import ThreatAnalysisRequest, ThreatAnalysisResponse
from app.services.email_parser import parse_email, parse_headers
from app.services.geolocation import geolocate_ip
from app.services.header_analyzer import analyze_headers
from app.services.ip_analyzer import extract_originating_ips
from app.services.nlp_analyzer import analyze_social_engineering
from app.services.risk_engine import score_threat
from app.services.url_analyzer import analyze_urls

router = APIRouter()


def _coerce_headers(headers: Any) -> dict[str, Any]:
    if headers is None:
        return {}
    return parse_headers(headers)


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is not None and str(value).strip() != "":
            return value
    return None


def _safe_module_result(module: str, errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "module": module,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
        "details": {},
        "errors": list(errors or []),
    }


@router.post("/threat-analysis", response_model=ThreatAnalysisResponse)
def post_threat_analysis(body: ThreatAnalysisRequest) -> dict[str, Any]:
    """Run the end-to-end email threat pipeline for manual or pasted email content."""
    payload = body.model_dump(exclude_none=True)

    email_candidate = payload.get("email")
    if isinstance(email_candidate, dict):
        candidate_body = _first_non_empty(
            email_candidate.get("body"),
            email_candidate.get("text"),
            email_candidate.get("email_text"),
        )
        candidate_headers = email_candidate.get("headers", {})
        candidate_subject = _first_non_empty(email_candidate.get("subject"))
        candidate_from = _first_non_empty(email_candidate.get("from"), email_candidate.get("sender"))
        candidate_to = _first_non_empty(email_candidate.get("to"), email_candidate.get("recipient"))
    else:
        candidate_body = None
        candidate_headers = {}
        candidate_subject = None
        candidate_from = None
        candidate_to = None

    raw_email = payload.get("raw_email")
    email_text = _first_non_empty(
        payload.get("email_text"),
        payload.get("email_body"),
        payload.get("body"),
        payload.get("text"),
        candidate_body,
    )
    if not email_text and raw_email:
        parsed_raw = parse_email(raw_email)
        email_text = _first_non_empty(parsed_raw.get("body"), parsed_raw.get("text"))
        candidate_headers = candidate_headers or parsed_raw.get("headers", {})
        candidate_subject = candidate_subject or parsed_raw.get("subject")
        candidate_from = candidate_from or parsed_raw.get("from")
        candidate_to = candidate_to or parsed_raw.get("to")

    headers = _coerce_headers(
        _first_non_empty(
            payload.get("headers"),
            payload.get("header"),
            candidate_headers,
        )
    )
    if not headers and raw_email:
        parsed_raw = parse_email(raw_email)
        headers = _coerce_headers(parsed_raw.get("headers", {}))

    subject = _first_non_empty(payload.get("subject"), candidate_subject)
    sender = _first_non_empty(
        payload.get("from_email"),
        payload.get("sender"),
        candidate_from,
    )
    recipient = _first_non_empty(payload.get("to"), payload.get("recipient"), candidate_to)

    if not email_text and raw_email:
        parsed_raw = parse_email(raw_email)
        email_text = _first_non_empty(parsed_raw.get("text"), parsed_raw.get("body"))

    email_meta = {
        "id": payload.get("id") or payload.get("email_id") or "manual-email",
        "subject": subject or "",
        "from": sender or "",
        "to": recipient or "",
    }

    if not email_text and raw_email is None:
        email_text = ""

    nlp_result = analyze_social_engineering(email_text)
    header_result = analyze_headers(headers)
    url_result = analyze_urls(email_text or "")
    ip_result = extract_originating_ips(headers)

    public_ip = None
    if isinstance(ip_result, dict):
        public_ip = (ip_result.get("details") or {}).get("chosen_sending_node")

    geolocation_result = _safe_module_result("geolocation", ["No public IP available for geolocation."])
    if public_ip:
        try:
            geolocation_result = geolocate_ip(str(public_ip))
        except Exception as exc:  # pragma: no cover - safety net for provider failures
            geolocation_result = _safe_module_result("geolocation", [f"Geolocation lookup failed: {exc}"])
            geolocation_result["details"] = {"ip_address": public_ip, "error": str(exc)}
    else:
        geolocation_result["details"] = {"ip_address": None, "error": "No public IP was available."}

    findings = {
        "nlp": nlp_result,
        "header_analysis": header_result,
        "url": url_result,
        "ip": ip_result,
        "geolocation": geolocation_result,
        "email_text": email_text,
        "enable_external": payload.get("enable_external", True),
    }

    final_result = score_threat(findings)

    final_result["email"] = email_meta
    final_result["top_reasons"] = final_result.get("top_reasons") or final_result.get("reasons") or []
    final_result["overall"] = {
        "risk_score": final_result.get("risk_score", 0),
        "risk_level": final_result.get("risk_level", "SAFE"),
        "classification": final_result.get("classification", final_result.get("risk_level", "SAFE")),
        "top_reasons": final_result["top_reasons"],
        "recommendation": final_result.get("recommendation", "No significant threat indicators detected."),
        "confidence": (
            "HIGH" if len(final_result["top_reasons"]) >= 3 else "MEDIUM" if final_result.get("risk_score", 0) > 0 else "LOW"
        ),
    }
    final_result["analyses"] = {
        "nlp": nlp_result,
        "header": header_result,
        "url": url_result,
        "ip": ip_result,
        "geolocation": geolocation_result,
        "threat_intelligence": final_result.get("threat_intelligence", {}),
    }
    final_result["disclaimer"] = (
        "Analysis provides security intelligence and risk assessment; "
        "it does not prove attacker identity."
    )

    return final_result
