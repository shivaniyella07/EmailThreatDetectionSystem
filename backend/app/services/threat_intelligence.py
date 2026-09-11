"""Threat intelligence correlation (Member 5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

KNOWLEDGE_PATH = Path(__file__).resolve().parents[1] / "data" / "threat_knowledge" / "threat_knowledge.json"


def _load_entries() -> list[dict[str, Any]]:
    if not KNOWLEDGE_PATH.exists():
        return []
    try:
        with KNOWLEDGE_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return []
    if isinstance(data, dict):
        entries = data.get("entries", [])
    elif isinstance(data, list):
        entries = data
    else:
        entries = []
    return [entry for entry in entries if isinstance(entry, dict)]


def _flatten_indicators(indicators: Any) -> list[str]:
    values: list[str] = []
    if isinstance(indicators, dict):
        for value in indicators.values():
            if isinstance(value, (list, tuple)):
                values.extend(str(item) for item in value if item is not None)
            elif value is not None:
                values.append(str(value))
    elif isinstance(indicators, (list, tuple)):
        values.extend(str(item) for item in indicators if item is not None)
    elif indicators is not None:
        values.append(str(indicators))
    return [value.strip() for value in values if value and value.strip()]


def correlate_indicators(indicators: dict[str, Any] | None) -> dict[str, Any]:
    """Correlate the aggregated findings against the local threat knowledge base."""
    entries = _load_entries()
    flattened = _flatten_indicators(indicators)

    matched: list[str] = []
    unmatched: list[str] = []

    if flattened:
        combined_text = "\n".join(flattened).lower()
        for entry in entries:
            attack_type = str(entry.get("attack_type", "unknown"))
            description = str(entry.get("description", ""))
            patterns = [str(item) for item in entry.get("example_patterns", []) or []]
            if any(pattern.lower() in combined_text for pattern in patterns):
                matched.append(attack_type)
                continue
            if attack_type.lower() in combined_text or description.lower() in combined_text:
                matched.append(attack_type)

        unmatched = [item for item in flattened if not any(item.lower() in entry.get("attack_type", "").lower() for entry in entries)]

    unique_matches = sorted(set(matched))
    score = min(100, len(unique_matches) * 25)

    result = {
        "module": "threat_intelligence",
        "risk_score": score,
        "risk_level": "SAFE" if score <= 30 else "SUSPICIOUS" if score <= 60 else "HIGH_RISK",
        "indicators": unique_matches,
        "details": {
            "matches": unique_matches,
            "unmatched_indicators": unmatched,
        },
        "errors": [],
    }

    if not unique_matches:
        result["indicators"] = []
        result["details"]["matches"] = []

    return result
