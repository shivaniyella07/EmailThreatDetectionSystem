"""URL extraction and textual analysis (Member 4).

Never automatically open or visit URLs. Analyze URL strings only.
"""

from __future__ import annotations

import re
from typing import Any

URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)


def _risk_level(score: int) -> str:
    if score <= 30:
        return "SAFE"
    if score <= 60:
        return "SUSPICIOUS"
    return "HIGH_RISK"


def analyze_urls(text: str) -> dict[str, Any]:
    """Extract URLs from email text and provide a lightweight suspicious-URL score."""
    source_text = str(text or "").strip()

    extracted_urls = []
    seen: set[str] = set()
    for match in URL_PATTERN.finditer(source_text):
        candidate = match.group(0).rstrip(".,;)")
        if candidate and candidate not in seen:
            seen.add(candidate)
            extracted_urls.append(candidate)

    suspicious_urls: list[str] = []
    matched_keywords: list[str] = []

    suspicious_keywords = [
        "verify",
        "login",
        "secure",
        "password",
        "account",
        "payment",
        "confirm",
        "urgent",
        "update",
        "reset",
    ]

    for url in extracted_urls:
        lowered = url.lower()
        if any(keyword in lowered for keyword in suspicious_keywords) or any(
            host in lowered for host in ["bit.ly", "tinyurl", "t.co", "goo.gl"]
        ):
            suspicious_urls.append(url)

    score = 0
    if extracted_urls:
        score += min(25, len(extracted_urls) * 5)
    if suspicious_urls:
        score += min(75, len(suspicious_urls) * 20)

    indicators: list[str] = []
    if extracted_urls:
        indicators.append(f"Found {len(extracted_urls)} URL(s) in the message.")
    if suspicious_urls:
        indicators.append("Suspicious URL patterns were detected in the extracted links.")
    if not extracted_urls:
        indicators.append("No URLs were detected in the provided email text.")

    details = {
        "extracted_urls": extracted_urls,
        "suspicious_urls": suspicious_urls,
        "matched_keywords": matched_keywords,
    }

    return {
        "module": "url",
        "risk_score": min(score, 100),
        "risk_level": _risk_level(min(score, 100)),
        "indicators": indicators,
        "details": details,
        "errors": [],
    }
