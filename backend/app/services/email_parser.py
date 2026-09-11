"""Email parsing helpers (Member 1 / shared).

This lightweight parser supports the manual paste workflow used by the
frontend dashboard. It never executes attachments or downloads content.
"""

from __future__ import annotations

from email import policy
from email.parser import Parser
from typing import Any


def _normalize_header_value(value: Any) -> Any:
    """Normalize repeated headers into strings or lists."""
    if isinstance(value, list):
        normalized = [str(item).strip() for item in value if item is not None and str(item).strip()]
        return normalized[0] if len(normalized) == 1 else normalized
    return str(value).strip() if value is not None else None


def parse_headers(headers: dict[str, Any] | list[tuple[str, Any]] | str | None) -> dict[str, Any]:
    """Normalize incoming headers into a plain dictionary keyed by header name."""
    if headers is None:
        return {}

    if isinstance(headers, dict):
        return {str(key): value for key, value in headers.items()}

    if isinstance(headers, str):
        normalized: dict[str, Any] = {}
        for line in headers.splitlines():
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            normalized[str(name).strip()] = value.strip()
        return normalized

    if isinstance(headers, (list, tuple)):
        normalized = {}
        for key, value in headers:
            normalized[str(key)] = value
        return normalized

    return {}


def parse_email(raw_email: str) -> dict[str, Any]:
    """Parse raw email text into a structured dict used by the manual analysis pipeline."""
    raw_text = str(raw_email or "").strip()
    if not raw_text:
        return {
            "body": "",
            "text": "",
            "headers": {},
            "subject": "",
            "from": "",
            "to": "",
        }

    parsed = Parser(policy=policy.default).parsestr(raw_text)

    headers: dict[str, Any] = {}
    for name, value in parsed.raw_items():
        current = headers.get(name)
        if current is None:
            headers[name] = _normalize_header_value(value)
        elif isinstance(current, list):
            current.append(_normalize_header_value(value))
        else:
            headers[name] = [current, _normalize_header_value(value)]

    payload = parsed.get_payload()
    body = ""
    if isinstance(payload, list):
        body = "\n".join(
            part.get_payload(decode=True).decode("utf-8", errors="replace")
            if isinstance(part.get_payload(decode=True), bytes)
            else str(part.get_payload(""))
            for part in payload
            if part.get_payload(decode=True) is not None or part.get_payload("")
        )
    elif payload is None:
        body = parsed.get_body(preferencelist=("plain", "html")) or ""
    else:
        body = parsed.get_body(preferencelist=("plain", "html")) or str(payload)

    body = body.replace("\r\n", "\n").strip()

    return {
        "body": body,
        "text": body,
        "headers": headers,
        "subject": parsed.get("Subject", "") or "",
        "from": parsed.get("From", "") or "",
        "to": parsed.get("To", "") or "",
    }
