"""IP geolocation intelligence (Member 4).

Results are approximate intelligence, not proof of attacker identity.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any


KNOWN_IP_LOCATIONS: dict[str, dict[str, Any]] = {
    "8.8.8.8": {
        "country": "United States",
        "region": "California",
        "city": "Mountain View",
        "isp": "Google LLC",
        "asn": "AS15169",
        "latitude": 37.4056,
        "longitude": -122.1141,
        "source": "approximate public-IP intelligence",
    },
    "1.1.1.1": {
        "country": "Australia",
        "region": "New South Wales",
        "city": "Sydney",
        "isp": "Cloudflare, Inc.",
        "asn": "AS13335",
        "latitude": -33.8688,
        "longitude": 151.2093,
        "source": "approximate public-IP intelligence",
    },
    "203.0.113.18": {
        "country": "Singapore",
        "region": "Singapore",
        "city": "Singapore",
        "isp": "Example ISP",
        "asn": "AS64500",
        "latitude": 1.3521,
        "longitude": 103.8198,
        "source": "approximate public-IP intelligence",
    },
}


def _risk_level(score: int) -> str:
    if score <= 30:
        return "SAFE"
    if score <= 60:
        return "SUSPICIOUS"
    return "HIGH_RISK"


def geolocate_ip(ip_address_value: str) -> dict[str, Any]:
    """Return approximate geolocation for a public IP address."""
    normalized_ip = str(ip_address_value or "").strip()

    result: dict[str, Any] = {
        "module": "geolocation",
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
        "details": {
            "ip_address": normalized_ip,
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "asn": None,
            "latitude": None,
            "longitude": None,
            "source": "approximate public-IP intelligence",
        },
        "errors": [],
    }

    if not normalized_ip:
        result["errors"].append("No IP address was provided for geolocation.")
        return result

    try:
        parsed_ip = ip_address(normalized_ip)
    except ValueError:
        result["errors"].append(f"Invalid IP address supplied: {normalized_ip}")
        return result

    if parsed_ip.is_private or parsed_ip.is_reserved:
        result["errors"].append("Only private or reserved IP space was supplied; geolocation was skipped.")
        result["details"]["ip_address"] = normalized_ip
        return result

    known = KNOWN_IP_LOCATIONS.get(normalized_ip)
    if known:
        result["details"].update(known)
        return result

    result["details"].update(
        {
            "country": "Unresolved",
            "region": "Unresolved",
            "city": "Unresolved",
            "isp": "Unknown",
            "asn": "Unknown",
            "latitude": None,
            "longitude": None,
        }
    )
    result["errors"].append("No geolocation mapping was available for the supplied public IP.")
    return result
