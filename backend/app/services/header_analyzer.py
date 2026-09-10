"""Email header and protocol forensics (Member 3).

Analyzes sender identity, routing headers, and authentication results
to produce explainable spoofing indicators.
"""

import re
from email.utils import parseaddr


def _get_header(headers: dict, name: str):
    """Get a header value case-insensitively."""
    if not isinstance(headers, dict):
        return None

    if name in headers:
        return headers[name]

    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return value

    return None


def _get_header_values(headers: dict, name: str) -> list:
    """Return a header as a list, handling strings and lists."""
    value = _get_header(headers, name)

    if value is None:
        return []

    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if item is not None]

    return [str(value).strip()]


def _extract_domain(value) -> str | None:
    """Extract a lowercase domain from an email address."""
    if not value:
        return None

    text = str(value).strip()
    _, address = parseaddr(text)

    if "@" not in address:
        return None

    domain = address.rsplit("@", 1)[1].strip().lower()

    if not domain or "." not in domain:
        return None

    return domain


def _normalize_auth_result(value: str, protocol: str) -> str:
    """Extract pass/fail/unknown authentication status."""
    if not value:
        return "unknown"

    text = str(value).lower()

    match = re.search(
        rf"\b{re.escape(protocol)}\s*=\s*"
        r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        text,
    )

    if not match:
        return "unknown"

    result = match.group(1)

    if result == "pass":
        return "pass"

    if result in {"fail", "softfail", "permerror", "temperror"}:
        return "fail"

    return "unknown"


def _risk_level(score: int) -> str:
    """Convert a 0-100 score into the contract's risk level."""
    if score <= 30:
        return "SAFE"

    if score <= 60:
        return "SUSPICIOUS"

    return "HIGH_RISK"


def analyze_headers(headers: dict) -> dict:
    """Analyze email headers and return an explainable forensic result."""
    result = {
        "module": "header",
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
        "details": {},
        "errors": [],
    }

    if not isinstance(headers, dict):
        result["errors"].append("Header input must be a dictionary.")
        return result

    from_value = _get_header(headers, "From")
    reply_to_value = _get_header(headers, "Reply-To")
    return_path_value = _get_header(headers, "Return-Path")
    message_id_value = _get_header(headers, "Message-ID")
    received_values = _get_header_values(headers, "Received")
    auth_values = _get_header_values(headers, "Authentication-Results")

    from_domain = _extract_domain(from_value)
    reply_to_domain = _extract_domain(reply_to_value)
    return_path_domain = _extract_domain(return_path_value)

    auth_text = " ".join(auth_values)

    spf = _normalize_auth_result(auth_text, "spf")
    dkim = _normalize_auth_result(auth_text, "dkim")
    dmarc = _normalize_auth_result(auth_text, "dmarc")

    result["details"] = {
        "from": str(from_value) if from_value else None,
        "reply_to": str(reply_to_value) if reply_to_value else None,
        "return_path": str(return_path_value) if return_path_value else None,
        "message_id": str(message_id_value) if message_id_value else None,
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "received_count": len(received_values),
        "received_chain": received_values,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "domain_mismatch": False,
    }

    score = 0

    # Missing important identity headers.
    if not from_value:
        result["errors"].append("Missing From header.")
    elif not from_domain:
        result["errors"].append("From header does not contain a valid email domain.")

    if not message_id_value:
        result["errors"].append("Missing Message-ID header.")

    if not received_values:
        result["errors"].append("Missing Received header.")

    if not auth_values:
        result["errors"].append("Missing Authentication-Results header.")

    # Rule 1: Reply-To domain mismatch.
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        score += 25
        result["details"]["domain_mismatch"] = True
        result["indicators"].append(
            "Reply-To domain differs from the From domain."
        )

    # Rule 2: From and Return-Path mismatch.
    if from_domain and return_path_domain and from_domain != return_path_domain:
        score += 20
        result["details"]["domain_mismatch"] = True
        result["indicators"].append(
            "Return-Path domain differs from the From domain."
        )

    # Rule 3: Authentication failures.
    if spf == "fail":
        score += 20
        result["indicators"].append("SPF authentication failed.")

    if dkim == "fail":
        score += 20
        result["indicators"].append("DKIM authentication failed.")

    if dmarc == "fail":
        score += 25
        result["indicators"].append("DMARC authentication failed.")

    # Rule 4: Suspicious routing.
    if len(received_values) > 10:
        score += 10
        result["indicators"].append(
            "Email contains an unusually long Received header chain."
        )

    # Rule 5: Suspicious sender-domain relationship.
    if (
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
        and reply_to_domain in {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com"}
    ):
        score += 10
        result["indicators"].append(
            "Reply-To uses a common consumer mailbox domain different from the sender domain."
        )

    # Cap the module score at the contract maximum.
    score = min(score, 100)

    result["risk_score"] = score
    result["risk_level"] = _risk_level(score)

    return result