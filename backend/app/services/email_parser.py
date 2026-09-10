"""Email parsing helpers (Member 1 / shared).

This parser intentionally normalizes email content without executing
attachments or fetching remote resources.
"""

from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from typing import Any


def _normalize_header_key(name: Any) -> str:
    return str(name).strip()


def _store_header(headers: dict[str, Any], name: Any, value: Any) -> None:
    key = _normalize_header_key(name)
    if key == "":
        return

    if key not in headers:
        headers[key] = value
        return

    existing = headers[key]
    if isinstance(existing, list):
        existing.append(value)
    else:
        headers[key] = [existing, value]


def parse_headers(raw_headers: Any) -> dict[str, Any]:
    """Normalize header input from dict or newline-delimited text into a dict."""
    if raw_headers is None:
        return {}

    if isinstance(raw_headers, dict):
        normalized: dict[str, Any] = {}
        for key, value in raw_headers.items():
            if isinstance(value, (list, tuple)):
                for item in value:
                    _store_header(normalized, key, str(item).strip())
            else:
                _store_header(normalized, key, str(value).strip())
        return normalized

    if isinstance(raw_headers, str):
        text = raw_headers.strip()
        if not text:
            return {}

        normalized: dict[str, Any] = {}
        current_name: str | None = None
        current_value: list[str] = []

        def flush_current() -> None:
            nonlocal current_name, current_value
            if current_name is None:
                return
            value = " ".join(part.strip() for part in current_value if part and part.strip())
            if value:
                _store_header(normalized, current_name, value)
            current_name = None
            current_value = []

        for raw_line in text.replace("\r\n", "\n").split("\n"):
            line = raw_line.strip()
            if not line:
                if current_name is not None:
                    continue
                continue

            if line.startswith((" ", "\t")) and current_name is not None:
                current_value.append(line.strip())
                continue

            if ":" in line:
                flush_current()
                name, value = line.split(":", 1)
                current_name = name.strip()
                current_value = [value.strip()]
                continue

            if current_name is not None:
                current_value.append(line)

        flush_current()
        return normalized

    if isinstance(raw_headers, (list, tuple)):
        normalized: dict[str, Any] = {}
        for item in raw_headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                _store_header(normalized, item[0], item[1])
        return normalized

    return {}


def _decode_header(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(str(part) for part in value if part is not None)
    return str(value)


def _extract_body(message: Any) -> str:
    if not hasattr(message, "walk"):
        return ""

    body_parts: list[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = (part.get("Content-Type") or "").lower()
        if "text/plain" not in content_type and "text/html" not in content_type:
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            try:
                decoded = payload.decode("utf-8", errors="replace")
            except Exception:  # pragma: no cover - defensive fallback
                decoded = payload.decode("latin-1", errors="replace")
        else:
            decoded = str(payload or "")
        body_parts.append(decoded)

    body = "\n".join(body_parts).strip()
    if not body:
        return ""

    body = re.sub(r"<[^>]+>", " ", body)
    body = re.sub(r"\s+", " ", body)
    return body.strip()


def parse_email(raw_email: str | dict | None) -> dict:
    """Parse raw email content into a safe, normalized dictionary."""

    if isinstance(raw_email, dict):
        headers = parse_headers(raw_email.get("headers"))
        body = raw_email.get("body") or raw_email.get("text") or raw_email.get("email_text") or ""
        return {
            "subject": raw_email.get("subject") or "",
            "from": raw_email.get("from") or raw_email.get("sender") or "",
            "to": raw_email.get("to") or raw_email.get("recipient") or "",
            "body": str(body or ""),
            "text": str(body or ""),
            "headers": headers,
            "urls": [],
        }

    if not isinstance(raw_email, str) or not raw_email.strip():
        return {
            "subject": "",
            "from": "",
            "to": "",
            "body": "",
            "text": "",
            "headers": {},
            "urls": [],
        }

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_email.encode("utf-8", errors="replace"))
    except Exception:
        return {
            "subject": "",
            "from": "",
            "to": "",
            "body": raw_email,
            "text": raw_email,
            "headers": {},
            "urls": [],
        }

    headers = {}
    for name, value in message.raw_items():
        if name is None:
            continue
        if name not in headers:
            headers[name] = _decode_header(value)
        elif isinstance(headers[name], list):
            headers[name].append(_decode_header(value))
        else:
            headers[name] = [headers[name], _decode_header(value)]

    body = _extract_body(message)
    if not body:
        body = message.get_body(preferencelist=("plain", "html"))
        if body is not None:
            body = body.get_payload(decode=True)
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            body = str(body or "")

    subject = _decode_header(message.get("Subject"))
    sender = _decode_header(message.get("From"))
    recipient = _decode_header(message.get("To"))

    urls = []
    for match in re.findall(r"(?:https?://|www\.)[^\s<>'\"]+", body, flags=re.IGNORECASE):
        urls.append(match.rstrip(".,!?;:)]}"))

    return {
        "subject": subject,
        "from": sender,
        "to": recipient,
        "body": body,
        "text": body,
        "headers": headers,
        "urls": urls,
    }
