"""Threat intelligence correlation (Member 5).

Consumes indicators already produced by Members 2, 3, and 4. Matching uses
the local knowledge file at ``app/data/threat_knowledge/threat_knowledge.json``.
Optional VirusTotal and AbuseIPDB lookups are environment-variable based and
never required for the MVP.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

MODULE_NAME = "threat_intelligence"
KNOWLEDGE_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "threat_knowledge"
    / "threat_knowledge.json"
)

EXTERNAL_TIMEOUT_SECONDS = float(os.getenv("THREAT_INTEL_TIMEOUT", "3"))
MAX_EXTERNAL_LOOKUPS = 3

SEVERITY_CONFIDENCE = {
    "CRITICAL": 95,
    "HIGH": 80,
    "MEDIUM": 55,
    "LOW": 30,
}

_KNOWLEDGE_CACHE: dict[str, Any] | None = None

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _contract_risk_level(score: int) -> str:
    """Map 0-100 to the shared module envelope bands."""
    if score <= 30:
        return "SAFE"
    if score <= 60:
        return "SUSPICIOUS"
    return "HIGH_RISK"


def reset_knowledge_cache() -> None:
    """Clear the in-memory knowledge cache (used by tests)."""
    global _KNOWLEDGE_CACHE
    _KNOWLEDGE_CACHE = None


def load_threat_knowledge(force_reload: bool = False) -> dict[str, Any]:
    """Load local threat knowledge. Returns empty structures on failure."""
    global _KNOWLEDGE_CACHE
    if _KNOWLEDGE_CACHE is not None and not force_reload:
        return _KNOWLEDGE_CACHE

    empty: dict[str, Any] = {"entries": [], "iocs": []}
    try:
        with KNOWLEDGE_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, ValueError):
        _KNOWLEDGE_CACHE = empty
        return empty

    if not isinstance(data, dict):
        _KNOWLEDGE_CACHE = empty
        return empty

    entries = data.get("entries") if isinstance(data.get("entries"), list) else []
    iocs = data.get("iocs") if isinstance(data.get("iocs"), list) else []
    _KNOWLEDGE_CACHE = {"entries": entries, "iocs": iocs}
    return _KNOWLEDGE_CACHE


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _details(module: dict[str, Any]) -> dict[str, Any]:
    details = module.get("details")
    return details if isinstance(details, dict) else {}


def _normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _normalize_domain(value: str) -> str | None:
    text = (value or "").strip().lower()
    if not text:
        return None
    if "://" in text:
        parsed = urlparse(text)
        text = (parsed.hostname or "").lower()
    if "@" in text and _EMAIL_RE.match(text):
        text = text.rsplit("@", 1)[1]
    text = text.strip(".").lower()
    if not text or "." not in text:
        return None
    if _normalize_ip(text):
        return None
    return text


def _normalize_url(value: str) -> str | None:
    text = (value or "").strip()
    if not text:
        return None
    return text.rstrip(".,;:)>]}").lower()


def _indicator_key(indicator_type: str, value: str) -> tuple[str, str]:
    return (indicator_type.lower(), value.lower())


def _add_indicator(
    collected: dict[tuple[str, str], dict[str, str]],
    value: str | None,
    indicator_type: str,
    source: str,
) -> None:
    if not value:
        return
    cleaned = str(value).strip()
    if not cleaned:
        return
    key = _indicator_key(indicator_type, cleaned)
    if key not in collected:
        collected[key] = {
            "value": cleaned,
            "type": indicator_type,
            "source": source,
        }


def _module_from_payload(payload: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        candidate = payload.get(key)
        if isinstance(candidate, dict):
            return candidate
    return {}


def extract_indicators(payload: dict[str, Any] | None) -> list[dict[str, str]]:
    """Collect IPs, domains, URLs, and sender identity from prior modules."""
    data = payload if isinstance(payload, dict) else {}
    collected: dict[tuple[str, str], dict[str, str]] = {}

    nlp = _module_from_payload(data, "nlp")
    header = _module_from_payload(data, "header_analysis", "header")
    url_mod = _module_from_payload(data, "url")
    geo = _module_from_payload(data, "geolocation")
    ip_mod = _module_from_payload(data, "ip")
    combined = _module_from_payload(data, "ip_url_analysis")

    header_details = _details(header) or header
    url_details = _details(url_mod) or url_mod
    geo_details = _details(geo) or geo
    ip_details = _details(ip_mod) or ip_mod

    for domain, source in (
        (header_details.get("from_domain"), "header.from_domain"),
        (header_details.get("reply_to_domain"), "header.reply_to_domain"),
        (header_details.get("return_path_domain"), "header.return_path_domain"),
        (header.get("sender_domain"), "header.sender_domain"),
        (combined.get("sender_domain"), "ip_url_analysis.sender_domain"),
    ):
        normalized = _normalize_domain(str(domain)) if domain else None
        _add_indicator(collected, normalized, "domain", source)

    for field in ("from", "reply_to", "return_path"):
        raw = header_details.get(field)
        if isinstance(raw, str) and "@" in raw:
            domain = _normalize_domain(raw)
            _add_indicator(collected, domain, "domain", f"header.{field}")

    origin_candidates = [
        combined.get("origin_ip"),
        combined.get("originating_ip"),
        combined.get("sender_ip"),
        ip_details.get("chosen_sending_node"),
        geo_details.get("chosen_sending_node"),
        geo.get("ip_address") if geo else None,
        geo_details.get("ip_address"),
    ]
    for candidate in origin_candidates:
        if isinstance(candidate, str):
            ip_value = _normalize_ip(candidate)
            _add_indicator(collected, ip_value, "ip", "origin_ip")

    for container in (ip_details, geo_details, combined):
        for key in ("public_ips", "extracted_ips", "ips"):
            for item in _as_list(container.get(key)):
                if isinstance(item, str):
                    _add_indicator(collected, _normalize_ip(item), "ip", "ip_analysis")

    url_values: list[str] = []
    for item in _as_list(url_details.get("urls")):
        if isinstance(item, str):
            url_values.append(item)
        elif isinstance(item, dict) and item.get("url"):
            url_values.append(str(item["url"]))
            hostname = item.get("hostname")
            if hostname:
                _add_indicator(
                    collected,
                    _normalize_domain(str(hostname)),
                    "domain",
                    "url.hostname",
                )
    for key in ("extracted_urls", "suspicious_urls", "ip_based_urls", "shortened_urls"):
        for item in _as_list(url_details.get(key)):
            if isinstance(item, str):
                url_values.append(item)
    for item in _as_list(combined.get("urls")):
        if isinstance(item, str):
            url_values.append(item)
        elif isinstance(item, dict) and item.get("url"):
            url_values.append(str(item["url"]))

    for raw_url in url_values:
        normalized_url = _normalize_url(raw_url)
        _add_indicator(collected, normalized_url, "url", "url_analysis")
        domain = _normalize_domain(raw_url)
        _add_indicator(collected, domain, "domain", "url_analysis")

    for item in _as_list(url_details.get("lookalike_domains")):
        if isinstance(item, str):
            _add_indicator(collected, _normalize_domain(item), "domain", "url.lookalike")

    nlp_details = _details(nlp)
    for label in _as_list(nlp_details.get("threat_labels")):
        if isinstance(label, str) and label.strip():
            _add_indicator(collected, label.strip().upper(), "attack_type", "nlp")

    for item in _as_list(data.get("indicators")):
        if isinstance(item, str) and item.strip():
            if _normalize_ip(item):
                _add_indicator(collected, _normalize_ip(item), "ip", "request")
            elif item.lower().startswith("http") or item.lower().startswith("www."):
                _add_indicator(collected, _normalize_url(item), "url", "request")
                _add_indicator(collected, _normalize_domain(item), "domain", "request")
            elif _normalize_domain(item):
                _add_indicator(collected, _normalize_domain(item), "domain", "request")
        elif isinstance(item, dict):
            value = item.get("value")
            itype = str(item.get("type") or "other")
            if isinstance(value, str):
                _add_indicator(collected, value, itype, str(item.get("source") or "request"))

    return list(collected.values())


def _ioc_index(iocs: list[Any]) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for item in iocs:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        itype = str(item.get("type") or "").strip().lower()
        if not value or not itype:
            continue
        if itype == "ip":
            normalized = _normalize_ip(value) or value.lower()
        elif itype == "domain":
            normalized = _normalize_domain(value) or value.lower()
        elif itype == "url":
            normalized = _normalize_url(value) or value.lower()
        else:
            normalized = value.lower()
        index[(itype, normalized)] = item
    return index


def _finding_from_ioc(
    indicator: dict[str, str],
    ioc: dict[str, Any],
) -> dict[str, Any]:
    severity = str(ioc.get("severity") or "HIGH").upper()
    confidence = ioc.get("confidence")
    if not isinstance(confidence, int):
        confidence = SEVERITY_CONFIDENCE.get(severity, 70)
    confidence = max(0, min(100, int(confidence)))
    reason = str(
        ioc.get("reason")
        or f"Threat-intelligence match found for {indicator['type']} {indicator['value']}"
    )
    return {
        "indicator": indicator["value"],
        "indicator_type": indicator["type"],
        "known": True,
        "suspicious": True,
        "threat_category": ioc.get("threat_category"),
        "confidence": confidence,
        "severity": severity,
        "matching_source": str(ioc.get("source") or "local_threat_knowledge"),
        "campaign": ioc.get("campaign"),
        "threat_actor": ioc.get("threat_actor"),
        "reason": reason,
    }


def _match_knowledge_entries(
    payload: dict[str, Any],
    entries: list[Any],
) -> list[dict[str, Any]]:
    """Match NLP labels and forensic phrases to local attack-type entries."""
    findings: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    nlp = _module_from_payload(payload, "nlp")
    nlp_details = _details(nlp)
    labels = {
        str(label).strip().upper()
        for label in _as_list(nlp_details.get("threat_labels"))
        if isinstance(label, str) and label.strip()
    }

    haystacks: list[str] = []
    for item in _as_list(nlp.get("indicators")):
        if isinstance(item, str):
            haystacks.append(item.lower())
    url_mod = _module_from_payload(payload, "url")
    url_details = _details(url_mod) or url_mod
    for item in _as_list(url_details.get("keyword_matches")):
        if isinstance(item, str):
            haystacks.append(item.lower())
    email_text = payload.get("email_text")
    if isinstance(email_text, str) and email_text.strip():
        haystacks.append(email_text.lower())
    combined_text = " ".join(haystacks)

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get("id") or "")
        attack_type = str(entry.get("attack_type") or "").upper()
        matched = False
        reason = ""

        if attack_type and attack_type in labels:
            matched = True
            reason = (
                f"NLP threat label '{attack_type}' matches local knowledge "
                f"entry {entry_id or attack_type}."
            )
        elif combined_text:
            patterns = [
                str(pattern).lower()
                for pattern in _as_list(entry.get("example_patterns"))
                if isinstance(pattern, str) and len(pattern) >= 8
            ]
            for pattern in patterns:
                if pattern in combined_text:
                    matched = True
                    reason = (
                        f"Indicator text matched local knowledge pattern "
                        f"'{pattern}' ({attack_type or entry_id})."
                    )
                    break

        if not matched or entry_id in seen_ids:
            continue
        seen_ids.add(entry_id)
        severity = str(entry.get("risk_level") or "MEDIUM").upper()
        findings.append(
            {
                "indicator": attack_type or entry_id or "knowledge_entry",
                "indicator_type": "attack_type",
                "known": True,
                "suspicious": True,
                "threat_category": attack_type or None,
                "confidence": SEVERITY_CONFIDENCE.get(severity, 55),
                "severity": severity,
                "matching_source": "local_threat_knowledge",
                "campaign": None,
                "threat_actor": None,
                "reason": reason,
            }
        )
    return findings


def _http_get_json(
    url: str,
    headers: dict[str, str],
    timeout: float,
) -> dict[str, Any] | None:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (
        urllib.error.URLError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError,
        OSError,
    ):
        return None
    return payload if isinstance(payload, dict) else None


def _lookup_abuseipdb(ip_address: str) -> dict[str, Any] | None:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return None
    query = urllib.parse.urlencode({"ipAddress": ip_address, "maxAgeInDays": "90"})
    url = f"https://api.abuseipdb.com/api/v2/check?{query}"
    data = _http_get_json(
        url,
        {
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "EmailThreatDetectionSystem/1.0",
        },
        EXTERNAL_TIMEOUT_SECONDS,
    )
    if not data:
        return None
    inner = data.get("data") if isinstance(data.get("data"), dict) else data
    score = inner.get("abuseConfidenceScore")
    try:
        score_int = int(score)
    except (TypeError, ValueError):
        return None
    if score_int < 25:
        return None
    severity = "CRITICAL" if score_int >= 75 else "HIGH" if score_int >= 50 else "MEDIUM"
    return {
        "indicator": ip_address,
        "indicator_type": "ip",
        "known": score_int >= 50,
        "suspicious": True,
        "threat_category": "ABUSE_REPORTS",
        "confidence": max(0, min(100, score_int)),
        "severity": severity,
        "matching_source": "abuseipdb",
        "campaign": None,
        "threat_actor": None,
        "reason": (
            f"AbuseIPDB reported abuse confidence {score_int} for originating IP."
        ),
    }


def _lookup_virustotal(indicator: dict[str, str]) -> dict[str, Any] | None:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return None
    itype = indicator["type"]
    value = indicator["value"]
    if itype == "ip":
        path = f"ip_addresses/{urllib.parse.quote(value)}"
    elif itype == "domain":
        path = f"domains/{urllib.parse.quote(value)}"
    elif itype == "url":
        url_id = urllib.parse.quote(value, safe="")
        path = f"urls/{url_id}"
    else:
        return None
    data = _http_get_json(
        f"https://www.virustotal.com/api/v3/{path}",
        {
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "EmailThreatDetectionSystem/1.0",
        },
        EXTERNAL_TIMEOUT_SECONDS,
    )
    if not data:
        return None
    attributes = (
        data.get("data", {}).get("attributes", {})
        if isinstance(data.get("data"), dict)
        else {}
    )
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    if malicious <= 0 and suspicious <= 0:
        return None
    severity = "CRITICAL" if malicious >= 5 else "HIGH" if malicious else "MEDIUM"
    return {
        "indicator": value,
        "indicator_type": itype,
        "known": malicious > 0,
        "suspicious": True,
        "threat_category": "MULTI_ENGINE_DETECTION",
        "confidence": min(100, 50 + malicious * 8 + suspicious * 4),
        "severity": severity,
        "matching_source": "virustotal",
        "campaign": None,
        "threat_actor": None,
        "reason": (
            f"VirusTotal reported {malicious} malicious and "
            f"{suspicious} suspicious detections."
        ),
    }


def _external_lookups(
    indicators: list[dict[str, str]],
    already_matched: set[tuple[str, str]],
    errors: list[str],
) -> list[dict[str, Any]]:
    """Optional enrichment. Never raises; never includes secrets."""
    findings: list[dict[str, Any]] = []
    lookups = 0
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not vt_key and not abuse_key:
        return findings

    for indicator in indicators:
        if lookups >= MAX_EXTERNAL_LOOKUPS:
            break
        key = _indicator_key(indicator["type"], indicator["value"])
        if key in already_matched:
            continue
        itype = indicator["type"]
        value = indicator["value"]
        try:
            if itype == "ip" and _is_public_ip(value):
                abuse = _lookup_abuseipdb(value) if abuse_key else None
                if abuse:
                    findings.append(abuse)
                    already_matched.add(key)
                    lookups += 1
                    continue
                vt = _lookup_virustotal(indicator) if vt_key else None
                if vt:
                    findings.append(vt)
                    already_matched.add(key)
                    lookups += 1
            elif itype in {"domain", "url"} and vt_key:
                vt = _lookup_virustotal(indicator)
                lookups += 1
                if vt:
                    findings.append(vt)
                    already_matched.add(key)
        except Exception as exc:  # noqa: BLE001 - external APIs must never break scoring
            errors.append(f"External threat-intelligence lookup failed: {exc}")
    return findings


def correlate_indicator_patterns(
    payload: dict[str, Any],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build multi-indicator correlations with explanations."""
    correlations: list[dict[str, Any]] = []
    header = _module_from_payload(payload, "header_analysis", "header")
    header_details = _details(header) or header
    nlp = _module_from_payload(payload, "nlp")
    url_mod = _module_from_payload(payload, "url")
    url_details = _details(url_mod) or url_mod

    known_ips = [
        item["indicator"]
        for item in findings
        if item.get("known") and item.get("indicator_type") == "ip"
    ]
    known_domains = [
        item["indicator"]
        for item in findings
        if item.get("known") and item.get("indicator_type") == "domain"
    ]
    known_urls = [
        item["indicator"]
        for item in findings
        if item.get("known") and item.get("indicator_type") == "url"
    ]
    suspicious_urls = _as_list(url_details.get("suspicious_urls"))
    lookalikes = _as_list(url_details.get("lookalike_domains"))

    if known_ips and (known_domains or lookalikes or suspicious_urls):
        correlations.append(
            {
                "pattern": "malicious_ip_and_suspicious_domain",
                "indicators": known_ips[:3] + (known_domains or [str(x) for x in lookalikes[:2]]),
                "explanation": "Malicious/suspicious IP correlated with a suspicious domain.",
                "severity": "CRITICAL",
            }
        )

    if known_domains and (known_urls or suspicious_urls):
        correlations.append(
            {
                "pattern": "suspicious_domain_and_phishing_url",
                "indicators": known_domains[:3] + [str(u) for u in (known_urls or suspicious_urls)[:2]],
                "explanation": "Suspicious domain correlated with a phishing or suspicious URL.",
                "severity": "HIGH",
            }
        )

    spf = str(header_details.get("spf") or header.get("spf") or "").lower()
    dkim = str(header_details.get("dkim") or header.get("dkim") or "").lower()
    dmarc = str(header_details.get("dmarc") or header.get("dmarc") or "").lower()
    mismatch = bool(header_details.get("domain_mismatch"))
    auth_fails = [name for name, value in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)) if value == "fail"]
    if len(auth_fails) >= 1 and mismatch:
        correlations.append(
            {
                "pattern": "auth_failure_and_domain_mismatch",
                "indicators": auth_fails + ["sender-domain mismatch"],
                "explanation": (
                    "Failed SPF/DKIM/DMARC combined with a sender-domain mismatch."
                ),
                "severity": "HIGH",
            }
        )
    elif len(auth_fails) >= 2:
        correlations.append(
            {
                "pattern": "multiple_authentication_failures",
                "indicators": auth_fails,
                "explanation": "Multiple email authentication checks failed.",
                "severity": "HIGH",
            }
        )

    nlp_score = _nlp_score(nlp)
    if findings and any(item.get("known") for item in findings) and nlp_score >= 61:
        correlations.append(
            {
                "pattern": "known_indicator_and_nlp_phishing",
                "indicators": [
                    item["indicator"]
                    for item in findings
                    if item.get("known")
                ][:3]
                + [f"nlp_score={nlp_score}"],
                "explanation": (
                    "Known malicious indicator correlated with a high NLP phishing score."
                ),
                "severity": "CRITICAL",
            }
        )

    campaigns: dict[str, list[str]] = {}
    for item in findings:
        campaign = item.get("campaign")
        if campaign:
            campaigns.setdefault(str(campaign), []).append(str(item.get("indicator")))
    for campaign, values in campaigns.items():
        if len(values) >= 2:
            correlations.append(
                {
                    "pattern": "same_campaign_cluster",
                    "indicators": values,
                    "explanation": (
                        f"Multiple indicators belong to the same threat campaign ({campaign})."
                    ),
                    "severity": "HIGH",
                }
            )

    if len(findings) >= 3:
        correlations.append(
            {
                "pattern": "multiple_suspicious_indicators",
                "indicators": [str(item.get("indicator")) for item in findings[:5]],
                "explanation": "Multiple suspicious indicators correlated.",
                "severity": "HIGH",
            }
        )

    return correlations


def _nlp_score(nlp: dict[str, Any]) -> int:
    if not nlp:
        return 0
    if isinstance(nlp.get("risk_score"), (int, float)):
        return max(0, min(100, int(round(float(nlp["risk_score"])))))
    confidence = nlp.get("confidence")
    if isinstance(confidence, (int, float)):
        value = float(confidence)
        if 0.0 <= value <= 1.0:
            return max(0, min(100, int(round(value * 100))))
        return max(0, min(100, int(round(value))))
    if nlp.get("is_phishing") is True:
        return 70
    return 0


def score_threat_intelligence(
    findings: list[dict[str, Any]],
    correlations: list[dict[str, Any]],
) -> int:
    """Deterministic 0-100 score for the threat-intelligence module."""
    if not findings:
        bonus = 10 if correlations else 0
        return min(100, bonus)

    score = 0
    for item in findings:
        severity = str(item.get("severity") or "MEDIUM").upper()
        if item.get("known"):
            score += {
                "CRITICAL": 50,
                "HIGH": 40,
                "MEDIUM": 25,
                "LOW": 12,
            }.get(severity, 25)
        elif item.get("suspicious"):
            score += 15
    for item in correlations:
        severity = str(item.get("severity") or "MEDIUM").upper()
        score += {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 6, "LOW": 3}.get(severity, 6)
    return max(0, min(100, score))


def correlate_indicators(indicators: dict | list | None) -> dict[str, Any]:
    """Correlate IOCs with local (and optional external) threat intelligence.

    Accepts either a prior-module payload dict or a list of indicator objects.
    """
    if isinstance(indicators, list):
        payload: dict[str, Any] = {"indicators": indicators}
    elif isinstance(indicators, dict):
        payload = indicators
    else:
        payload = {}
    return analyze_threat_intelligence(payload)


def analyze_threat_intelligence(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Run Member 5 threat-intelligence correlation and return a module envelope."""
    errors: list[str] = []
    if payload is None:
        payload = {}
    elif not isinstance(payload, dict):
        errors.append("Threat-intelligence input must be an object.")
        payload = {}

    for key in ("nlp", "header_analysis", "header", "url", "geolocation", "ip", "ip_url_analysis"):
        value = payload.get(key)
        if value is not None and not isinstance(value, dict):
            errors.append(f"{key} must be an object when provided.")

    knowledge = load_threat_knowledge()
    extracted = extract_indicators(payload)
    ioc_map = _ioc_index(knowledge.get("iocs") or [])

    findings: list[dict[str, Any]] = []
    unmatched: list[dict[str, str]] = []
    matched_keys: set[tuple[str, str]] = set()

    for indicator in extracted:
        itype = indicator["type"]
        value = indicator["value"]
        lookup_value = value
        if itype == "ip":
            lookup_value = _normalize_ip(value) or value.lower()
        elif itype == "domain":
            lookup_value = _normalize_domain(value) or value.lower()
        elif itype == "url":
            lookup_value = _normalize_url(value) or value.lower()
        ioc = ioc_map.get((itype, lookup_value))
        if ioc is None and itype == "url":
            domain = _normalize_domain(value)
            if domain:
                ioc = ioc_map.get(("domain", domain))
        if ioc:
            finding = _finding_from_ioc(indicator, ioc)
            findings.append(finding)
            matched_keys.add(_indicator_key(itype, value))
        elif itype != "attack_type":
            unmatched.append(indicator)

    findings.extend(_match_knowledge_entries(payload, knowledge.get("entries") or []))

    enable_external = payload.get("enable_external", True)
    if enable_external is not False:
        try:
            findings.extend(_external_lookups(extracted, matched_keys, errors))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"External threat intelligence unavailable: {exc}")

    correlations = correlate_indicator_patterns(payload, findings)
    ti_score = score_threat_intelligence(findings, correlations)
    readable = [str(item.get("reason")) for item in findings if item.get("reason")]
    for item in correlations:
        readable.append(str(item.get("explanation")))

    return {
        "module": MODULE_NAME,
        "risk_score": ti_score,
        "risk_level": _contract_risk_level(ti_score),
        "indicators": readable,
        "details": {
            "findings": findings,
            "unmatched_indicators": unmatched,
            "correlated_indicators": correlations,
            "knowledge_entries": len(knowledge.get("entries") or []),
            "knowledge_iocs": len(knowledge.get("iocs") or []),
            "external_enabled": bool(
                os.getenv("VIRUSTOTAL_API_KEY", "").strip()
                or os.getenv("ABUSEIPDB_API_KEY", "").strip()
            )
            and enable_external is not False,
        },
        "errors": errors,
        "findings": findings,
        "unmatched_indicators": unmatched,
        "correlated_indicators": correlations,
    }
