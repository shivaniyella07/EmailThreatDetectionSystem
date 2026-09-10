"""IP geolocation intelligence service (Member 4).

Location information is approximate network intelligence and does not
establish attacker identity.

The service works without an API by using a development fallback.
An optional external provider can be configured through environment
variables without hardcoding API keys.
"""

import ipaddress
import json
import os
import urllib.error
import urllib.request


DISCLAIMER = (
    "Location information is approximate network intelligence "
    "and does not establish attacker identity."
)


def _base_result(ip_address: str | None) -> dict:
    """Create the standard geolocation result structure."""

    return {
        "ip_address": ip_address,
        "country": None,
        "region": None,
        "city": None,
        "isp": None,
        "asn": None,
        "latitude": None,
        "longitude": None,
        "approximate": True,
        "source": "development_fallback",
        "error": None,
        "intelligence_note": DISCLAIMER,
    }


def _is_public_ip(ip_address: str) -> bool:
    """Return True only for globally routable public IP addresses."""

    try:
        return ipaddress.ip_address(ip_address).is_global
    except ValueError:
        return False


def _development_fallback(ip_address: str) -> dict:
    """Return a safe result when no external provider is configured."""

    result = _base_result(ip_address)

    result["source"] = "development_fallback"

    result["intelligence_note"] = (
        DISCLAIMER
        + " No external geolocation provider is configured, "
        "so location fields are unavailable."
    )

    return result


def _external_lookup(ip_address: str) -> dict:
    """Query an optional environment-configured geolocation provider.

    Expected provider response fields:

        country
        region
        city
        isp
        asn
        latitude
        longitude

    The URL must contain {ip}, for example:

        https://provider.example/{ip}

    API keys are read from the GEOLOCATION_API_KEY environment
    variable and are never hardcoded.
    """

    provider_url = os.getenv("GEOLOCATION_PROVIDER_URL", "").strip()

    if not provider_url:
        return _development_fallback(ip_address)

    if "{ip}" not in provider_url:
        result = _development_fallback(ip_address)
        result["error"] = (
            "GEOLOCATION_PROVIDER_URL must contain the {ip} placeholder."
        )
        return result

    url = provider_url.replace("{ip}", ip_address)

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Astra-Email-Threat-Detection/1.0",
        },
        method="GET",
    )

    api_key = os.getenv("GEOLOCATION_API_KEY", "").strip()

    if api_key:
        request.add_header("X-API-Key", api_key)

    try:
        timeout = float(
            os.getenv("GEOLOCATION_TIMEOUT", "3")
        )

        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        result = _development_fallback(ip_address)

        result["error"] = (
            f"External geolocation provider unavailable: {exc}"
        )

        return result

    if not isinstance(data, dict):
        result = _development_fallback(ip_address)
        result["error"] = (
            "External geolocation provider returned invalid data."
        )
        return result

    result = _base_result(ip_address)

    result["source"] = "external_provider"

    result["country"] = data.get("country")
    result["region"] = data.get("region")
    result["city"] = data.get("city")
    result["isp"] = data.get("isp")
    result["asn"] = data.get("asn")
    result["latitude"] = data.get("latitude")
    result["longitude"] = data.get("longitude")

    result["intelligence_note"] = DISCLAIMER

    return result


def geolocate_ip(ip_address: str) -> dict:
    """Validate and geolocate a public IP address.

    The function does not identify a person or attacker.
    It provides approximate network intelligence only.
    """

    if not isinstance(ip_address, str):
        result = _base_result(None)

        result["error"] = (
            "IP address must be provided as a string."
        )

        return result

    cleaned_ip = ip_address.strip()

    try:
        normalized_ip = str(
            ipaddress.ip_address(cleaned_ip)
        )

    except ValueError:
        result = _base_result(cleaned_ip)

        result["error"] = "Invalid IP address."

        return result

    # Private, localhost, link-local, reserved, multicast,
    # documentation and other non-global addresses are rejected.
    if not _is_public_ip(normalized_ip):
        result = _base_result(normalized_ip)

        result["error"] = (
            "Private, local, reserved, or non-routable "
            "IP address cannot be publicly geolocated."
        )

        return result

    return _external_lookup(normalized_ip)