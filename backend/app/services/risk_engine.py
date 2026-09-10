"""Explainable overall risk scoring 0–100 (Member 5).

Consumes module envelopes already produced by Members 2, 3, and 4 plus
local threat-intelligence correlation. Does not re-parse emails, extract
URLs/IPs, or run NLP.
"""

from __future__ import annotations

from typing import Any

from app.services.threat_intelligence import analyze_threat_intelligence

# Weights match docs/api_contract.md (five live module scores in this repo).
WEIGHTS = {
    "nlp": 0.25,
    "header": 0.25,
    "url": 0.20,
    "threat_intelligence": 0.20,
    "geolocation": 0.10,
}

# Overall Member 5 bands (SAFE / SUSPICIOUS / HIGH_RISK / CRITICAL).
RISK_LEVEL_MAX = {
    "SAFE": 24,
    "SUSPICIOUS": 49,
    "HIGH_RISK": 74,
    "CRITICAL": 100,
}

# Shared module/overall classification still used by Members 1 and 6.
CLASSIFICATION_MAX = {
    "SAFE": 30,
    "SUSPICIOUS": 60,
    "HIGH_RISK": 100,
}

CORRELATION_BONUS_CAP = 12

RECOMMENDATIONS = {
    "SAFE": (
        "No significant threat indicators detected. Continue normal email handling."
    ),
    "SUSPICIOUS": (
        "Exercise caution and verify the sender before interacting with "
        "links or attachments."
    ),
    "HIGH_RISK": (
        "Do not interact with links or attachments. Verify the sender through "
        "an independent channel and investigate the reported indicators."
    ),
    "CRITICAL": (
        "Treat this email as a high-confidence threat. Quarantine the message "
        "and initiate a security investigation."
    ),
}


def _clamp_score(value: Any) -> int:
    """Return an integer score in 0–100."""
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, score))


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _details(module: dict[str, Any]) -> dict[str, Any]:
    details = module.get("details")
    return details if isinstance(details, dict) else {}


def _pick_module(findings: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        candidate = findings.get(key)
        if isinstance(candidate, dict):
            return candidate
    return {}


def _normalize_findings(findings: dict[str, Any] | None) -> dict[str, Any]:
    """Accept either a flat Member 5 payload or a nested analyses object."""
    if findings is None:
        return {}
    if not isinstance(findings, dict):
        return {}

    data = dict(findings)
    analyses = data.get("analyses")
    if isinstance(analyses, dict):
        for key, value in analyses.items():
            data.setdefault(key, value)
    return data


def risk_level_from_score(score: int) -> str:
    """Map 0–100 onto SAFE / SUSPICIOUS / HIGH_RISK / CRITICAL."""
    if score <= RISK_LEVEL_MAX["SAFE"]:
        return "SAFE"
    if score <= RISK_LEVEL_MAX["SUSPICIOUS"]:
        return "SUSPICIOUS"
    if score <= RISK_LEVEL_MAX["HIGH_RISK"]:
        return "HIGH_RISK"
    return "CRITICAL"


def classification_from_score(score: int) -> str:
    """Map 0–100 onto the shared API-contract bands."""
    if score <= CLASSIFICATION_MAX["SAFE"]:
        return "SAFE"
    if score <= CLASSIFICATION_MAX["SUSPICIOUS"]:
        return "SUSPICIOUS"
    return "HIGH_RISK"


def recommendation_for(level: str) -> str:
    """Return a defensive handling recommendation for a risk level."""
    return RECOMMENDATIONS.get(level, RECOMMENDATIONS["SUSPICIOUS"])


def _nlp_score(nlp: dict[str, Any]) -> int:
    if not nlp:
        return 0
    if nlp.get("risk_score") is not None:
        return _clamp_score(nlp.get("risk_score"))
    confidence = nlp.get("confidence")
    if isinstance(confidence, (int, float)):
        value = float(confidence)
        if 0.0 <= value <= 1.0:
            return _clamp_score(value * 100)
        return _clamp_score(value)
    if nlp.get("is_phishing") is True:
        return 70
    return 0


def _header_score(header: dict[str, Any]) -> int:
    """Use Member 3's module score, or derive from auth fields they already set."""
    if not header:
        return 0
    if header.get("risk_score") is not None:
        return _clamp_score(header.get("risk_score"))

    details = _details(header) or header
    score = 0
    if str(details.get("spf") or header.get("spf") or "").lower() == "fail":
        score += 20
    if str(details.get("dkim") or header.get("dkim") or "").lower() == "fail":
        score += 20
    if str(details.get("dmarc") or header.get("dmarc") or "").lower() == "fail":
        score += 25
    if details.get("domain_mismatch") is True:
        score += 25
    return _clamp_score(score)


def _url_score(url_mod: dict[str, Any], combined: dict[str, Any]) -> int:
    source = url_mod or combined
    if not source:
        return 0
    if source.get("risk_score") is not None and url_mod:
        return _clamp_score(url_mod.get("risk_score"))
    if combined.get("risk_score") is not None and not url_mod:
        return _clamp_score(combined.get("risk_score"))
    return 0


def _geo_score(geo: dict[str, Any], ip_mod: dict[str, Any]) -> int:
    if geo.get("risk_score") is not None:
        return _clamp_score(geo.get("risk_score"))
    if ip_mod.get("risk_score") is not None:
        return _clamp_score(ip_mod.get("risk_score"))
    return 0


def _auth_status(header: dict[str, Any], name: str) -> str:
    details = _details(header) or header
    return str(details.get(name) or header.get(name) or "").lower()


def _collect_reasons(
    nlp: dict[str, Any],
    header: dict[str, Any],
    url_mod: dict[str, Any],
    combined: dict[str, Any],
    threat_intel: dict[str, Any],
    nlp_score: int,
) -> list[str]:
    """Build explainable reasons only from findings that actually exist."""
    reasons: list[str] = []
    seen: set[str] = set()

    def add(reason: str) -> None:
        text = str(reason).strip().rstrip(".")
        if text and text not in seen:
            seen.add(text)
            reasons.append(text)

    if nlp.get("is_phishing") is True or nlp_score >= 61:
        add("High phishing probability detected by NLP module")
    elif nlp_score >= 31:
        add("AI/NLP module reported suspicious phishing language")

    nlp_details = _details(nlp)
    for label in _as_list(nlp_details.get("threat_labels")):
        if isinstance(label, str) and label.strip():
            add(f"NLP threat label: {label.strip()}")

    if _auth_status(header, "spf") == "fail":
        add("SPF authentication failed")
    if _auth_status(header, "dkim") == "fail":
        add("DKIM authentication failed")
    if _auth_status(header, "dmarc") == "fail":
        add("DMARC authentication failed")

    header_details = _details(header) or header
    if header_details.get("domain_mismatch") is True:
        add("Suspicious sender domain detected")
    for item in _as_list(header.get("indicators")):
        if isinstance(item, str):
            add(item)

    url_details = _details(url_mod) or url_mod
    if _as_list(url_details.get("suspicious_urls")) or _as_list(combined.get("urls")):
        if _as_list(url_details.get("suspicious_urls")):
            add("Suspicious URL detected")
    if _as_list(url_details.get("lookalike_domains")):
        add("Suspicious sender domain detected")
    for item in _as_list(url_mod.get("indicators")):
        if isinstance(item, str):
            add(item)

    for finding in _as_list(threat_intel.get("findings")):
        if not isinstance(finding, dict):
            continue
        if finding.get("known") and finding.get("indicator_type") == "ip":
            add("Malicious IP found in threat intelligence")
        elif finding.get("known") and finding.get("indicator_type") == "domain":
            add("Known malicious domain detected")
        elif finding.get("known") and finding.get("indicator_type") == "url":
            add("Suspicious URL detected")
        if finding.get("reason"):
            add(str(finding["reason"]))

    for item in _as_list(threat_intel.get("correlated_indicators")):
        if isinstance(item, dict) and item.get("explanation"):
            add(str(item["explanation"]))

    return reasons


def _independent_signal_count(
    nlp_score: int,
    header_score: int,
    url_score: int,
    ti_score: int,
    geo_score: int,
    header: dict[str, Any],
    threat_intel: dict[str, Any],
) -> int:
    """Count distinct high-signal categories for a capped correlation bonus."""
    count = 0
    if nlp_score >= 50:
        count += 1
    if header_score >= 40 or _auth_status(header, "spf") == "fail":
        count += 1
    if url_score >= 30:
        count += 1
    if ti_score >= 40 or any(
        isinstance(item, dict) and item.get("known")
        for item in _as_list(threat_intel.get("findings"))
    ):
        count += 1
    if geo_score >= 40:
        count += 1
    return count


def _correlation_bonus(signal_count: int, correlations: list[Any]) -> tuple[int, list[str]]:
    """Strengthen the score when independent signals agree, without unbounded stacking."""
    extra_reasons: list[str] = []
    bonus = 0
    if signal_count >= 3:
        bonus += 8
        extra_reasons.append("Multiple independent threat indicators detected.")
    elif signal_count >= 2:
        bonus += 4
        extra_reasons.append("Multiple suspicious indicators correlated")

    if len(correlations) >= 2:
        bonus += 4
    elif len(correlations) == 1 and signal_count < 2:
        bonus += 2

    return min(CORRELATION_BONUS_CAP, bonus), extra_reasons


def score_threat(findings: dict | None) -> dict:
    """Compute an explainable overall threat score from prior-module findings.

    Missing or malformed module payloads are treated as score 0 and never raise.
    """
    errors: list[str] = []
    if findings is not None and not isinstance(findings, dict):
        errors.append("Findings must be an object.")
        findings = {}

    data = _normalize_findings(findings)

    for key in (
        "nlp",
        "header_analysis",
        "header",
        "url",
        "geolocation",
        "ip",
        "ip_url_analysis",
        "threat_intelligence",
    ):
        value = data.get(key)
        if value is not None and not isinstance(value, dict):
            errors.append(f"{key} must be an object when provided.")

    nlp = _pick_module(data, "nlp")
    header = _pick_module(data, "header_analysis", "header")
    url_mod = _pick_module(data, "url")
    geo = _pick_module(data, "geolocation")
    ip_mod = _pick_module(data, "ip")
    combined = _pick_module(data, "ip_url_analysis")

    existing_ti = _pick_module(data, "threat_intelligence")
    if existing_ti.get("findings") or existing_ti.get("module") == "threat_intelligence":
        threat_intel = existing_ti
        if "correlated_indicators" not in threat_intel:
            threat_intel = dict(threat_intel)
            threat_intel["correlated_indicators"] = _as_list(
                _details(threat_intel).get("correlated_indicators")
            )
    else:
        try:
            threat_intel = analyze_threat_intelligence(
                {
                    "nlp": nlp,
                    "header_analysis": header,
                    "header": header,
                    "url": url_mod,
                    "geolocation": geo,
                    "ip": ip_mod,
                    "ip_url_analysis": combined,
                    "indicators": data.get("indicators"),
                    "email_text": data.get("email_text"),
                    "enable_external": data.get("enable_external", True),
                }
            )
        except Exception as exc:  # noqa: BLE001 - scoring must remain available
            errors.append(f"Threat intelligence unavailable: {exc}")
            threat_intel = {
                "module": "threat_intelligence",
                "risk_score": 0,
                "risk_level": "SAFE",
                "indicators": [],
                "details": {},
                "errors": [str(exc)],
                "findings": [],
                "unmatched_indicators": [],
                "correlated_indicators": [],
            }

    nlp_score = _nlp_score(nlp)
    header_score = _header_score(header)
    url_score = _url_score(url_mod, combined)
    geo_score = _geo_score(geo, ip_mod)
    ti_score = _clamp_score(threat_intel.get("risk_score"))

    weighted = (
        WEIGHTS["nlp"] * nlp_score
        + WEIGHTS["header"] * header_score
        + WEIGHTS["url"] * url_score
        + WEIGHTS["threat_intelligence"] * ti_score
        + WEIGHTS["geolocation"] * geo_score
    )

    correlations = _as_list(threat_intel.get("correlated_indicators"))
    signal_count = _independent_signal_count(
        nlp_score,
        header_score,
        url_score,
        ti_score,
        geo_score,
        header,
        threat_intel,
    )
    bonus, bonus_reasons = _correlation_bonus(signal_count, correlations)

    risk_score = _clamp_score(weighted + bonus)
    risk_level = risk_level_from_score(risk_score)
    classification = classification_from_score(risk_score)

    reasons = _collect_reasons(
        nlp,
        header,
        url_mod,
        combined,
        threat_intel,
        nlp_score,
    )
    for extra in bonus_reasons:
        if extra not in reasons:
            reasons.append(extra)

    if risk_score == 0 and not reasons:
        reasons.append("No significant threat indicators detected.")

    ti_errors = _as_list(threat_intel.get("errors"))
    all_errors = [str(item) for item in (errors + ti_errors) if item]

    findings_list = _as_list(threat_intel.get("findings"))
    unmatched = _as_list(threat_intel.get("unmatched_indicators"))

    threat_intelligence = {
        "module": "threat_intelligence",
        "risk_score": ti_score,
        "risk_level": str(threat_intel.get("risk_level") or classification_from_score(ti_score)),
        "indicators": _as_list(threat_intel.get("indicators")),
        "details": _as_dict(threat_intel.get("details")),
        "errors": ti_errors,
        "findings": findings_list,
        "unmatched_indicators": unmatched,
    }

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,
        "reasons": reasons,
        "top_reasons": reasons,
        "recommendation": recommendation_for(risk_level),
        "threat_intelligence": threat_intelligence,
        "correlated_indicators": correlations,
        "category_scores": {
            "nlp": nlp_score,
            "header": header_score,
            "url": url_score,
            "threat_intelligence": ti_score,
            "geolocation": geo_score,
        },
        "weights": dict(WEIGHTS),
        "correlation_bonus": bonus,
        "errors": all_errors,
        "overall": {
            "risk_score": risk_score,
            "classification": classification,
            "risk_level": risk_level,
            "confidence": "HIGH" if signal_count >= 3 else "MEDIUM" if signal_count else "LOW",
        },
    }
