"""URL extraction and textual analysis .

Never automatically open, visit, fetch, or execute URLs.
Analyze URL strings only.
"""

import difflib
import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "secure",
    "update",
    "password",
    "account",
    "signin",
    "confirm",
    "bank",
    "wallet",
    "urgent",
    "invoice",
}

SHORTENED_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
}

# Common legitimate domains used for explainable lookalike detection.
KNOWN_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "outlook": "outlook.com",
}


def _risk_level(score: int) -> str:
    """Convert a risk score into the project's standard risk level."""
    if score <= 30:
        return "SAFE"
    if score <= 60:
        return "SUSPICIOUS"
    return "HIGH_RISK"


def _is_ip_address(hostname: str) -> bool:
    """Return True when the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _get_registered_domain(hostname: str) -> str:
    """Get a simple registrable-domain approximation.

    This intentionally uses only standard-library logic.
    """
    parts = hostname.split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


def _detect_lookalike(hostname: str) -> list:
    """Detect explainable brand lookalike or impersonation patterns."""
    if not hostname or _is_ip_address(hostname):
        return []

    registered_domain = _get_registered_domain(hostname)
    domain_name = registered_domain.split(".")[0]

    matches = []

    for brand, legitimate_domain in KNOWN_BRANDS.items():

        # Exact legitimate domain should never be flagged.
        if registered_domain == legitimate_domain:
            continue

        # Brand name appears as a subdomain of another domain.
        if brand in hostname.split(".") and registered_domain != legitimate_domain:
            matches.append(
                f"Domain contains the brand name '{brand}' "
                f"but is registered under '{registered_domain}'."
            )
            continue

        # Compare domain name with the legitimate brand name.
        similarity = difflib.SequenceMatcher(
            None,
            domain_name.lower(),
            brand.lower(),
        ).ratio()

        # High similarity can indicate a small spelling modification.
        if 0.80 <= similarity < 1.0:
            matches.append(
                f"Domain '{registered_domain}' closely resembles "
                f"'{legitimate_domain}'."
            )

    return matches


def analyze_urls(text: str) -> dict:
    """Extract and score URLs from text without visiting them."""

    if not isinstance(text, str):
        return {
            "module": "url",
            "risk_score": 0,
            "risk_level": "SAFE",
            "indicators": [],
            "details": {
                "urls": [],
                "extracted_urls": [],
                "suspicious_urls": [],
                "ip_based_urls": [],
                "keyword_matches": [],
                "shortened_urls": [],
                "lookalike_domains": [],
            },
            "errors": ["Input must be a string."],
        }

    # Find HTTP/HTTPS URLs and www URLs in the email text.
    url_pattern = r"(?:https?://|www\.)[^\s<>'\"]+"
    raw_urls = re.findall(url_pattern, text, flags=re.IGNORECASE)

    extracted_urls = []
    suspicious_urls = []
    ip_based_urls = []
    keyword_matches = []
    shortened_urls = []
    lookalike_domains = []
    indicators = []
    structured_urls = []

    total_score = 0

    for raw_url in raw_urls:

        # Remove punctuation commonly attached to URLs in email text.
        clean_url = raw_url.rstrip(".,!?;:)]}")

        if clean_url in extracted_urls:
            continue

        extracted_urls.append(clean_url)

        # Add a scheme to www URLs so urlparse can analyze them.
        parse_target = (
            clean_url
            if clean_url.lower().startswith(("http://", "https://"))
            else "http://" + clean_url
        )

        try:
            parsed = urlparse(parse_target)
            hostname = (parsed.hostname or "").lower()
        except ValueError:
            hostname = ""

        url_score = 0
        url_indicators = []
        found_keywords = []
        is_ip_based = False
        is_shortened = False
        uses_punycode = False
        excessive_subdomains = False
        lookalike_matches = []

        # ---------------------------------------------------------
        # 1. IP address used directly as URL host
        # ---------------------------------------------------------
        if _is_ip_address(hostname):
            is_ip_based = True
            url_score += 25

            ip_based_urls.append(clean_url)

            url_indicators.append(
                "URL uses an IP address instead of a domain name."
            )

        # ---------------------------------------------------------
        # 2. Suspicious keywords
        # ---------------------------------------------------------
        url_text = clean_url.lower()

        for keyword in sorted(SUSPICIOUS_KEYWORDS):
            if re.search(rf"\b{re.escape(keyword)}\b", url_text):
                found_keywords.append(keyword)

        if found_keywords:
            url_score += min(20, len(found_keywords) * 5)

            for keyword in found_keywords:
                if keyword not in keyword_matches:
                    keyword_matches.append(keyword)

            url_indicators.append(
                "URL contains suspicious keywords."
            )

        # ---------------------------------------------------------
        # 3. Known URL shortening service
        # ---------------------------------------------------------
        if hostname in SHORTENED_DOMAINS:
            is_shortened = True
            url_score += 15

            shortened_urls.append(clean_url)

            url_indicators.append(
                "URL uses a known URL-shortening service."
            )

        # ---------------------------------------------------------
        # 4. Punycode
        # ---------------------------------------------------------
        if "xn--" in hostname:
            uses_punycode = True
            url_score += 20

            if hostname not in lookalike_domains:
                lookalike_domains.append(hostname)

            url_indicators.append(
                "Domain uses punycode and may require "
                "lookalike-domain review."
            )

        # ---------------------------------------------------------
        # 5. Excessive subdomains
        # ---------------------------------------------------------
        domain_parts = hostname.split(".") if hostname else []

        if len(domain_parts) >= 5:
            excessive_subdomains = True
            url_score += 10

            url_indicators.append(
                "URL contains an unusually high number of subdomains."
            )

        # ---------------------------------------------------------
        # 6. Suspicious URL structure
        # ---------------------------------------------------------
        if parsed.username or parsed.password:
            url_score += 15

            url_indicators.append(
                "URL contains embedded user information before the domain."
            )

        # ---------------------------------------------------------
        # 7. Lookalike / typosquatting detection
        # ---------------------------------------------------------
        lookalike_matches = _detect_lookalike(hostname)

        if lookalike_matches:
            url_score += 20

            if hostname not in lookalike_domains:
                lookalike_domains.append(hostname)

            url_indicators.extend(lookalike_matches)

        # ---------------------------------------------------------
        # Calculate this URL's risk
        # ---------------------------------------------------------
        url_score = min(url_score, 100)

        if url_indicators:
            if clean_url not in suspicious_urls:
                suspicious_urls.append(clean_url)

        total_score += url_score

        # Structured information for EVERY extracted URL.
        structured_urls.append(
            {
                "url": clean_url,
                "hostname": hostname,
                "risk_score": url_score,
                "risk_level": _risk_level(url_score),
                "indicators": url_indicators,
                "keyword_matches": found_keywords,
                "is_ip_address": is_ip_based,
                "is_shortened": is_shortened,
                "uses_punycode": uses_punycode,
                "excessive_subdomains": excessive_subdomains,
                "lookalike_matches": lookalike_matches,
            }
        )

    # Keep overall score within the project's 0–100 range.
    total_score = min(total_score, 100)

    if not extracted_urls:
        indicators = []
    else:
        # Create a unique overall indicator list.
        for url_info in structured_urls:
            for indicator in url_info["indicators"]:
                if indicator not in indicators:
                    indicators.append(indicator)

    return {
        "module": "url",
        "risk_score": total_score,
        "risk_level": _risk_level(total_score),
        "indicators": indicators,
        "details": {
            # Required structured information for every URL.
            "urls": structured_urls,

            # Keep these summary fields for compatibility
            # with the rest of the project.
            "extracted_urls": extracted_urls,
            "suspicious_urls": suspicious_urls,
            "ip_based_urls": ip_based_urls,
            "keyword_matches": keyword_matches,
            "shortened_urls": shortened_urls,
            "lookalike_domains": lookalike_domains,
        },
        "errors": [],
    }