import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

PHISHING_EMAIL = {
    "email_text": """
URGENT: Your PayPal account has been suspended.

We detected unusual activity on your account.
Verify your account immediately:
https://secure-login-example.com/verify

Enter your username and password to prevent permanent account closure.
If you do not verify within 30 minutes, your account will be permanently disabled.

Thank you,
PayPal Security Team
""",
    "headers": {
        "From": "PayPal Security <security@paypal.com>",
        "Reply-To": "security-alert@gmail.com",
        "Return-Path": "<security-alert@gmail.com>",
        "Message-ID": "<alert-12345@example.com>",
        "Received": [
            "from suspicious-mail.example (192.168.1.25) by mx.example.com",
            "from external-host.example (8.8.8.8) by mail.example.com",
        ],
        "Authentication-Results": (
            "mx.example.com; "
            "spf=fail smtp.mailfrom=paypal.com; "
            "dkim=fail header.d=paypal.com; "
            "dmarc=fail header.from=paypal.com"
        ),
    },
}

SAFE_EMAIL = {
    "email_text": "Hi team, thanks for the project update. The meeting is at 3 PM tomorrow.",
    "headers": {
        "From": "hello@example.com",
        "Reply-To": "hello@example.com",
        "Return-Path": "<hello@example.com>",
        "Message-ID": "<safe-123@example.com>",
        "Received": [
            "from mail.example.com (203.0.113.44) by mx.example.com",
        ],
        "Authentication-Results": (
            "mx.example.com; spf=pass smtp.mailfrom=example.com; "
            "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
        ),
    },
}


def test_get_health() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["service"] == "EmailThreatDetectionSystem"


def test_phishing_email_analysis() -> None:
    response = client.post("/api/threat-analysis", json=PHISHING_EMAIL)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["risk_score"] >= 0
    assert body["risk_level"] in {"SAFE", "SUSPICIOUS", "HIGH_RISK"}
    assert body["overall"]["risk_level"] == body["risk_level"]
    assert "analyses" in body
    assert "nlp" in body["analyses"]
    assert "header" in body["analyses"]
    assert "url" in body["analyses"]
    assert body["analyses"]["nlp"]["risk_score"] > 0
    assert body["analyses"]["header"]["risk_score"] > 0
    assert body["analyses"]["url"]["risk_score"] >= 0
    assert "threat_intelligence" in body["analyses"]
    assert "errors" in body
    assert isinstance(body["errors"], list)


def test_safe_email_analysis() -> None:
    response = client.post("/api/threat-analysis", json=SAFE_EMAIL)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["risk_score"] <= 60
    assert body["risk_level"] in {"SAFE", "SUSPICIOUS"}
    assert body["classification"] in {"SAFE", "SUSPICIOUS"}


def test_missing_headers_are_handled() -> None:
    response = client.post(
        "/api/threat-analysis",
        json={
            "email_text": "Hi there, this is a routine note from the team.",
            "headers": {},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "analyses" in body
    assert isinstance(body["errors"], list)


def test_suspicious_url_email() -> None:
    response = client.post(
        "/api/threat-analysis",
        json={
            "email_text": "Reset your account now: https://secure-login-example.com/verify",
            "headers": {
                "From": "security@paypal.com",
                "Reply-To": "security@paypal.com",
                "Return-Path": "<security@paypal.com>",
                "Message-ID": "<demo-1@example.com>",
                "Received": ["from smtp.example (8.8.8.8) by mx.example.com"],
                "Authentication-Results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["analyses"]["url"]["risk_score"] > 0
    suspicious = body["analyses"]["url"]["details"].get("suspicious_urls", [])
    assert suspicious or body["analyses"]["url"]["indicators"]


def test_spf_dkim_dmarc_failures() -> None:
    response = client.post(
        "/api/threat-analysis",
        json={
            "email_text": "Urgent action required.",
            "headers": {
                "From": "support@bank-example.com",
                "Reply-To": "alerts@gmail.com",
                "Return-Path": "<alerts@gmail.com>",
                "Message-ID": "<demo-2@example.com>",
                "Received": ["from mail.example.com (8.8.8.8) by mx.example.com"],
                "Authentication-Results": (
                    "mx.example.com; spf=fail smtp.mailfrom=bank-example.com; "
                    "dkim=fail header.d=bank-example.com; dmarc=fail header.from=bank-example.com"
                ),
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["analyses"]["header"]["risk_score"] >= 60
    details = body["analyses"]["header"]["details"]
    assert details.get("spf") == "fail"
    assert details.get("dkim") == "fail"
    assert details.get("dmarc") == "fail"


def test_string_form_headers_are_parsed_for_m3_and_m4() -> None:
    headers_text = """From: PayPal Security <security@paypal.com>
Reply-To: security-alert@gmail.com
Return-Path: <security-alert@gmail.com>
Message-ID: <alert-12345@example.com>
Received: from suspicious-mail.example (192.168.1.25) by mx.example.com
Received: from external-host.example (8.8.8.8) by mail.example.com
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypal.com; dkim=fail header.d=paypal.com; dmarc=fail header.from=paypal.com
"""
    response = client.post(
        "/api/threat-analysis",
        json={
            "email_text": "URGENT: Verify your account immediately.",
            "headers": headers_text,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    header = body["analyses"]["header"]
    assert header["risk_score"] >= 60
    assert header["details"]["spf"] == "fail"
    assert header["details"]["dkim"] == "fail"
    assert header["details"]["dmarc"] == "fail"
    assert "Reply-To domain differs from the From domain." in header["indicators"]
    ip_info = body["analyses"]["ip"]
    extracted_ips = ip_info["details"]["extracted_ips"]
    assert "192.168.1.25" in extracted_ips
    assert "8.8.8.8" in extracted_ips
    assert ip_info["details"]["public_ips"]
    assert "8.8.8.8" in ip_info["details"]["public_ips"]
    geo = body["analyses"]["geolocation"]
    assert geo.get("ip_address") in {"8.8.8.8", None}


def test_geolocation_failure_does_not_crash(monkeypatch) -> None:
    monkeypatch.setenv("GEOLOCATION_PROVIDER_URL", "https://nope.invalid/{ip}")
    response = client.post(
        "/api/threat-analysis",
        json={
            "email_text": "Verify your account now.",
            "headers": {
                "From": "support@paypal.com",
                "Reply-To": "support@paypal.com",
                "Return-Path": "<support@paypal.com>",
                "Message-ID": "<demo-3@example.com>",
                "Received": ["from external-host.example (8.8.8.8) by mx.example.com"],
                "Authentication-Results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "geolocation" in body["analyses"]
    assert body["analyses"]["geolocation"].get("source") in {"development_fallback", "external_provider"}
    assert isinstance(body["errors"], list)


def test_final_response_contains_m5_fields() -> None:
    response = client.post("/api/threat-analysis", json=PHISHING_EMAIL)
    assert response.status_code == 200, response.text
    body = response.json()
    assert "risk_score" in body
    assert "risk_level" in body
    assert body["risk_level"] in {"SAFE", "SUSPICIOUS", "HIGH_RISK"}
    assert "classification" in body
    assert "threat_intelligence" in body
    assert "overall" in body


def test_no_secrets_in_api_response() -> None:
    response = client.post("/api/threat-analysis", json=PHISHING_EMAIL)
    assert response.status_code == 200, response.text
    raw = json.dumps(response.json())
    for key in ("GEOLOCATION_API_KEY", "THREAT_INTEL_API_KEY", "client_secret", "refresh_token", "secret"):
        assert key.lower() not in raw.lower()
