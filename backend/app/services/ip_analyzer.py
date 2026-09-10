"""Originating IP extraction from Received headers (Member 4)."""

import ipaddress
import re


def _is_public_ip(ip_address: str) -> bool:
    """Return True only for globally routable public IP addresses."""

    try:
        ip = ipaddress.ip_address(ip_address)

        # is_global excludes private, loopback, reserved,
        # multicast, link-local, unspecified and documentation ranges.
        return ip.is_global

    except ValueError:
        return False


def _extract_ip_addresses(header: str) -> list:
    """Extract valid IPv4 and IPv6 addresses from one header."""

    # IPv4 candidates.
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    # IPv6 candidates.
    ipv6_pattern = r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:]+(?![0-9A-Fa-f:])"

    matches = re.findall(
        f"{ipv4_pattern}|{ipv6_pattern}",
        header,
        flags=re.IGNORECASE,
    )

    valid_ips = []

    for candidate in matches:
        try:
            normalized_ip = str(ipaddress.ip_address(candidate))

            if normalized_ip not in valid_ips:
                valid_ips.append(normalized_ip)

        except ValueError:
            # Ignore invalid IP-looking strings.
            continue

    return valid_ips


def extract_originating_ips(headers: dict) -> dict:
    """Extract public IP addresses from Received headers.

    The function does not contact or identify any remote system.
    It only analyzes IP addresses already present in email headers.
    """

    if not isinstance(headers, dict):
        return {
            "module": "ip",
            "risk_score": 0,
            "risk_level": "SAFE",
            "indicators": [],
            "details": {
                "extracted_ips": [],
                "public_ips": [],
                "chosen_sending_node": None,
                "origin_selection_note": (
                    "No origin candidate could be selected."
                ),
            },
            "errors": [
                "Headers must be provided as a dictionary."
            ],
        }

    received_headers = headers.get("Received", [])

    if isinstance(received_headers, str):
        received_headers = [received_headers]

    if not isinstance(received_headers, list):
        return {
            "module": "ip",
            "risk_score": 0,
            "risk_level": "SAFE",
            "indicators": [],
            "details": {
                "extracted_ips": [],
                "public_ips": [],
                "chosen_sending_node": None,
                "origin_selection_note": (
                    "No origin candidate could be selected."
                ),
            },
            "errors": [
                "Received headers must be a string or list."
            ],
        }

    extracted_ips = []
    public_ips = []

    # Received headers are normally ordered newest hop first.
    # Therefore, the last usable public IP is treated as the
    # earliest reasonable sending node.
    for header in received_headers:

        if not isinstance(header, str):
            continue

        header_ips = _extract_ip_addresses(header)

        for ip_address in header_ips:

            if ip_address not in extracted_ips:
                extracted_ips.append(ip_address)

            if _is_public_ip(ip_address):
                if ip_address not in public_ips:
                    public_ips.append(ip_address)

    chosen_sending_node = (
        public_ips[-1] if public_ips else None
    )

    indicators = []

    if extracted_ips:
        indicators.append(
            "IP address(es) extracted from Received headers."
        )

    if public_ips:
        indicators.append(
            "Private, local, and non-routable IP addresses were excluded."
        )

    if chosen_sending_node:
        indicators.append(
            "Earliest reasonable public sending node selected "
            "from the Received header chain."
        )

    return {
        "module": "ip",
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": indicators,
        "details": {
            "extracted_ips": extracted_ips,
            "public_ips": public_ips,
            "chosen_sending_node": chosen_sending_node,
            "origin_selection_note": (
                "The selected IP is an approximate origin candidate "
                "based on Received-header order. It does not establish "
                "attacker identity."
            ),
        },
        "errors": [],
    }