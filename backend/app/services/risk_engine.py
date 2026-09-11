"""Explainable risk scoring 0–100 (Member 5).

Classification: SAFE, SUSPICIOUS, or HIGH RISK.
"""

from __future__ import annotations

from typing import Any

from app.services.threat_intelligence import correlate_indicators


def _risk_level(score: int) -> str:
    if score <= 30:
        return "SAFE"
    if score <= 60:
        return "SUSPICIOUS"
    return "HIGH_RISK"


def _module_score(module_result: dict[str, Any] | None) -> int:
    if not isinstance(module_result, dict):
        return 0
    score = module_result.get("risk_score")
    if score is None:
        return 0
    return int(score)


def _collect_indicators(module_result: dict[str, Any] | None) -> list[str]:
    if not isinstance(module_result, dict):
        return []

    collected: list[str] = []
    for indicator in module_result.get("indicators", []) or []:
        if isinstance(indicator, str) and indicator.strip():
            collected.append(indicator.strip())
    return collected


def score_threat(findings: dict[str, Any]) -> dict[str, Any]:
    """Compute the weighted overall score and return explainable findings."""
    nlp_result = findings.get("nlp") or {}
    header_result = findings.get("header_analysis") or {}
    url_result = findings.get("url") or {}
    ip_result = findings.get("ip") or {}
    geolocation_result = findings.get("geolocation") or {}

    category_scores = {
        "nlp": _module_score(nlp_result),
        "header": _module_score(header_result),
        "url": _module_score(url_result),
        "ip": _module_score(ip_result),
        "geolocation": _module_score(geolocation_result),
    }

    threat_intelligence = correlate_indicators(
        {
            "nlp": _collect_indicators(nlp_result),
            "header": _collect_indicators(header_result),
            "url": _collect_indicators(url_result),
            "ip": _collect_indicators(ip_result),
            "geolocation": _collect_indicators(geolocation_result),
        }
    )
    category_scores["threat_intelligence"] = _module_score(threat_intelligence)

    overall_score = int(
        round(
            0.25 * category_scores["nlp"]
            + 0.25 * category_scores["header"]
            + 0.20 * category_scores["url"]
            + 0.20 * category_scores["threat_intelligence"]
            + 0.10 * category_scores["geolocation"]
        )
    )
    overall_score = max(0, min(100, overall_score))

    top_reasons: list[str] = []
    seen_reasons: set[str] = set()

    for module_result in (nlp_result, header_result, url_result, ip_result, geolocation_result, threat_intelligence):
        for indicator in _collect_indicators(module_result):
            if indicator not in seen_reasons:
                seen_reasons.add(indicator)
                top_reasons.append(indicator)

    top_reasons = top_reasons[:6]

    recommendation = "No significant threat indicators detected."
    if overall_score >= 61:
        recommendation = "Quarantine the message, block the sender, and escalate for investigation."
    elif overall_score >= 31:
        recommendation = "Flag the message for review and monitor sender behavior closely."

    result = {
        "risk_score": overall_score,
        "risk_level": _risk_level(overall_score),
        "classification": _risk_level(overall_score),
        "category_scores": category_scores,
        "top_reasons": top_reasons,
        "recommendation": recommendation,
        "threat_intelligence": threat_intelligence,
        "correlation_bonus": threat_intelligence.get("risk_score", 0),
    }

    return result
