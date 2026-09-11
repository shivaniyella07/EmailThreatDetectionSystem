"""Originating IP extraction from Received headers (Member 4)."""

from __future__ import annotations

import re
from ipaddress import ip_address
from typing import Any

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _risk_level(score: int) -> str:
    if score <= 30:
        return "SAFE"
    if score <= 60:
        return "SUSPICIOUS"
    return "HIGH_RISK"


def _extract_ips_from_text(text: str) -> list[str]:
    candidates: list[str] = []
    for token in IPV4_PATTERN.findall(text):
        try:
            ip = ip_address(token)
        except ValueError:
            continue
        if str(ip).startswith("127.") or str(ip) == "0.0.0.0":
            continue
        candidates.append(str(ip))
    return candidates


def extract_originating_ips(headers: dict[str, Any] | None) -> dict[str, Any]:
    """Extract IPs from Received headers and choose the most relevant sending node."""
    headers = headers or {}

    received_values: list[str] = []
    if isinstance(headers, dict):
        raw_received = headers.get("Received", [])
        if isinstance(raw_received, str):
            received_values = [raw_received]
        elif isinstance(raw_received, (list, tuple)):
            received_values = [str(item) for item in raw_received if item is not None]

    extracted_ips: list[str] = []
    for raw_value in received_values:
        for ip_value in _extract_ips_from_text(str(raw_value)):
            if ip_value not in extracted_ips:
                extracted_ips.append(ip_value)

    public_ips = [ip for ip in extracted_ips if not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.")]
    chosen_sending_node = public_ips[0] if public_ips else (extracted_ips[0] if extracted_ips else None)

    score = min(100, len(public_ips) * 15 + len(extracted_ips) * 5)

    result = {
        "module": "ip",
        "risk_score": score,
        "risk_level": _risk_level(score),
        "indicators": [],
        "details": {
            "extracted_ips": extracted_ips,
            "public_ips": public_ips,
            "chosen_sending_node": chosen_sending_node,
        },
        "errors": [],
    }

    if not extracted_ips:
        result["errors"].append("No IP addresses were detected in Received headers.")
        result["indicators"].append("No originating IPs were identified from the email headers.")
    elif not public_ips:
        result["errors"].append("No public IPs were found in the Received chain.")
        result["indicators"].append("Only private or loopback IP addresses were identified.")

    return result
