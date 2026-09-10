from backend.app.services.header_analyzer import analyze_headers


def test_legitimate_email():
    headers = {
        "From": "Alice <alice@example.com>",
        "Reply-To": "alice@example.com",
        "Return-Path": "<alice@example.com>",
        "Message-ID": "<12345@example.com>",
        "Received": "from mail.example.com by mx.example.net",
        "Authentication-Results": "mx.example.net; spf=pass dkim=pass dmarc=pass",
    }

    result = analyze_headers(headers)

    assert result["risk_level"] == "SAFE"
    assert result["risk_score"] == 0
    assert result["details"]["spf"] == "pass"
    assert result["details"]["dkim"] == "pass"
    assert result["details"]["dmarc"] == "pass"
    assert result["details"]["domain_mismatch"] is False
    assert result["errors"] == []

    print("TEST 1 PASSED: Legitimate email")


def test_reply_to_mismatch():
    headers = {
        "From": "Security Team <security@example.com>",
        "Reply-To": "attacker@gmail.com",
        "Return-Path": "<security@example.com>",
        "Message-ID": "<abc123@example.com>",
        "Received": "from mail.example.com by mx.example.net",
        "Authentication-Results": "mx.example.net; spf=pass dkim=pass dmarc=pass",
    }

    result = analyze_headers(headers)

    assert result["risk_level"] == "SUSPICIOUS"
    assert result["details"]["domain_mismatch"] is True
    assert "Reply-To domain differs from the From domain." in result["indicators"]

    print("TEST 2 PASSED: Reply-To mismatch")


def test_authentication_failures():
    headers = {
        "From": "Security Team <security@example.com>",
        "Reply-To": "security@example.com",
        "Return-Path": "<security@example.com>",
        "Message-ID": "<fail123@example.com>",
        "Received": "from suspicious.example.net by mx.example.net",
        "Authentication-Results": (
            "mx.example.net; spf=fail dkim=fail dmarc=fail"
        ),
    }

    result = analyze_headers(headers)

    assert result["risk_level"] == "HIGH_RISK"
    assert result["details"]["spf"] == "fail"
    assert result["details"]["dkim"] == "fail"
    assert result["details"]["dmarc"] == "fail"

    print("TEST 3 PASSED: SPF/DKIM/DMARC failures")


def test_missing_headers():
    headers = {
        "From": "Unknown Sender <sender@example.com>"
    }

    result = analyze_headers(headers)

    assert result["module"] == "header"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"
    assert result["details"]["spf"] == "unknown"
    assert result["details"]["dkim"] == "unknown"
    assert result["details"]["dmarc"] == "unknown"
    assert len(result["errors"]) > 0

    print("TEST 4 PASSED: Missing/incomplete headers")


if __name__ == "__main__":
    test_legitimate_email()
    test_reply_to_mismatch()
    test_authentication_failures()
    test_missing_headers()

    print("ALL HEADER FORENSICS TESTS PASSED")
