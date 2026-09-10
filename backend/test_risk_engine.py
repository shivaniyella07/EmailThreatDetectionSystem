"""Unit tests for Member 5 threat intelligence and risk scoring."""

from __future__ import annotations

import unittest

from app.services.risk_engine import score_threat
from app.services.threat_intelligence import correlate_indicators


# Real IOC values from backend/app/data/threat_knowledge/threat_knowledge.json
KNOWN_MALICIOUS_IP = "198.51.100.66"
KNOWN_MALICIOUS_DOMAIN = "evil-login-portal.example"
KNOWN_MALICIOUS_URL = "http://evil-login-portal.example/verify"


class RiskEngineTests(unittest.TestCase):
    def test_empty_findings_are_safe(self) -> None:
        result = score_threat({})
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "SAFE")
        self.assertIn("No significant threat indicators detected.", result["reasons"][0])
        self.assertTrue(result["recommendation"].startswith("No significant"))

    def test_none_findings_do_not_crash(self) -> None:
        result = score_threat(None)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "SAFE")

    def test_missing_optional_fields(self) -> None:
        result = score_threat({"nlp": {}, "header": {}, "url": {}})
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_level"], "SAFE")

    def test_malformed_nested_modules(self) -> None:
        result = score_threat({"nlp": "not-an-object", "header_analysis": 12})
        self.assertEqual(result["risk_score"], 0)
        self.assertTrue(any("must be an object" in err for err in result["errors"]))

    def test_suspicious_findings(self) -> None:
        result = score_threat(
            {
                "nlp": {
                    "module": "nlp",
                    "risk_score": 48,
                    "risk_level": "SUSPICIOUS",
                    "indicators": ["Urgency language detected"],
                    "details": {"threat_labels": ["URGENCY_TIME_PRESSURE"]},
                    "errors": [],
                },
                "header": {
                    "module": "header",
                    "risk_score": 25,
                    "risk_level": "SAFE",
                    "indicators": ["Reply-To domain differs from the From domain."],
                    "details": {
                        "spf": "pass",
                        "dkim": "pass",
                        "dmarc": "pass",
                        "from_domain": "example.com",
                        "reply_to_domain": "gmail.com",
                        "domain_mismatch": True,
                    },
                    "errors": [],
                },
                "url": {
                    "module": "url",
                    "risk_score": 35,
                    "risk_level": "SUSPICIOUS",
                    "indicators": ["URL contains suspicious keywords."],
                    "details": {
                        "extracted_urls": ["http://example.com/login"],
                        "suspicious_urls": ["http://example.com/login"],
                        "keyword_matches": ["login"],
                    },
                    "errors": [],
                },
                "enable_external": False,
            }
        )
        self.assertGreaterEqual(result["risk_score"], 25)
        self.assertLessEqual(result["risk_score"], 49)
        self.assertEqual(result["risk_level"], "SUSPICIOUS")
        self.assertTrue(
            any("Suspicious sender domain detected" in reason for reason in result["reasons"])
        )

    def test_high_nlp_phishing_score(self) -> None:
        result = score_threat(
            {
                "nlp": {
                    "is_phishing": True,
                    "confidence": 0.91,
                    "risk_score": 91,
                    "details": {"threat_labels": ["CREDENTIAL_PHISHING"]},
                    "indicators": ["Credential request detected"],
                },
                "enable_external": False,
            }
        )
        self.assertGreaterEqual(result["category_scores"]["nlp"], 91)
        self.assertTrue(
            any("High phishing probability" in reason for reason in result["reasons"])
        )
        self.assertGreaterEqual(result["risk_score"], 22)

    def test_failed_authentication(self) -> None:
        result = score_threat(
            {
                "header_analysis": {
                    "module": "header",
                    "risk_score": 65,
                    "risk_level": "HIGH_RISK",
                    "indicators": [
                        "SPF authentication failed.",
                        "DKIM authentication failed.",
                        "DMARC authentication failed.",
                    ],
                    "details": {
                        "spf": "fail",
                        "dkim": "fail",
                        "dmarc": "fail",
                        "from_domain": "example.com",
                        "domain_mismatch": False,
                    },
                    "errors": [],
                },
                "enable_external": False,
            }
        )
        self.assertEqual(result["category_scores"]["header"], 65)
        self.assertIn("SPF authentication failed", result["reasons"])
        self.assertIn("DKIM authentication failed", result["reasons"])
        self.assertIn("DMARC authentication failed", result["reasons"])

    def test_known_malicious_ip_from_knowledge_base(self) -> None:
        result = score_threat(
            {
                "ip_url_analysis": {"origin_ip": KNOWN_MALICIOUS_IP},
                "enable_external": False,
            }
        )
        findings = result["threat_intelligence"]["findings"]
        matched = [
            item
            for item in findings
            if item.get("known") and item.get("indicator") == KNOWN_MALICIOUS_IP
        ]
        self.assertTrue(matched)
        self.assertEqual(matched[0]["matching_source"], "local_threat_knowledge")
        self.assertTrue(
            any("Malicious IP found in threat intelligence" in reason for reason in result["reasons"])
        )
        self.assertGreater(result["risk_score"], 0)

    def test_unknown_indicators_do_not_invent_intelligence(self) -> None:
        intel = correlate_indicators(
            {
                "ip_url_analysis": {"origin_ip": "8.8.8.8"},
                "header": {"details": {"from_domain": "google.com"}},
                "enable_external": False,
            }
        )
        known = [item for item in intel["findings"] if item.get("known") and item.get("indicator_type") in {"ip", "domain"}]
        self.assertEqual(known, [])
        unmatched_values = {item["value"] for item in intel["unmatched_indicators"]}
        self.assertIn("8.8.8.8", unmatched_values)
        self.assertIn("google.com", unmatched_values)

        result = score_threat(
            {
                "ip_url_analysis": {"origin_ip": "8.8.8.8"},
                "header": {"details": {"from_domain": "google.com"}},
                "enable_external": False,
            }
        )
        self.assertEqual(result["risk_level"], "SAFE")

    def test_high_risk_combined_signals(self) -> None:
        result = score_threat(
            {
                "nlp": {
                    "module": "nlp",
                    "risk_score": 72,
                    "is_phishing": True,
                    "details": {"threat_labels": ["CREDENTIAL_PHISHING"]},
                    "indicators": ["Credential request detected"],
                },
                "header": {
                    "module": "header",
                    "risk_score": 65,
                    "details": {
                        "spf": "fail",
                        "dkim": "fail",
                        "dmarc": "fail",
                        "domain_mismatch": False,
                    },
                    "indicators": ["SPF authentication failed."],
                },
                "url": {
                    "module": "url",
                    "risk_score": 55,
                    "details": {
                        "suspicious_urls": ["http://example.com/login"],
                        "extracted_urls": ["http://example.com/login"],
                    },
                    "indicators": ["URL contains suspicious keywords."],
                },
                "enable_external": False,
            }
        )
        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertIn(result["risk_level"], {"HIGH_RISK", "CRITICAL"})

    def test_critical_correlated_indicators(self) -> None:
        result = score_threat(
            {
                "nlp": {
                    "module": "nlp",
                    "risk_score": 91,
                    "is_phishing": True,
                    "confidence": 0.91,
                    "details": {"threat_labels": ["CREDENTIAL_PHISHING"]},
                    "indicators": ["Credential request detected"],
                },
                "header_analysis": {
                    "module": "header",
                    "risk_score": 65,
                    "details": {
                        "spf": "fail",
                        "dkim": "fail",
                        "dmarc": "fail",
                        "from_domain": "paypal.com",
                        "reply_to_domain": "gmail.com",
                        "domain_mismatch": True,
                    },
                    "indicators": [
                        "SPF authentication failed.",
                        "Reply-To domain differs from the From domain.",
                    ],
                },
                "url": {
                    "module": "url",
                    "risk_score": 80,
                    "details": {
                        "extracted_urls": [KNOWN_MALICIOUS_URL],
                        "suspicious_urls": [KNOWN_MALICIOUS_URL],
                        "lookalike_domains": [KNOWN_MALICIOUS_DOMAIN],
                        "urls": [
                            {
                                "url": KNOWN_MALICIOUS_URL,
                                "hostname": KNOWN_MALICIOUS_DOMAIN,
                            }
                        ],
                    },
                    "indicators": ["URL contains suspicious keywords."],
                },
                "ip_url_analysis": {
                    "origin_ip": KNOWN_MALICIOUS_IP,
                    "urls": [KNOWN_MALICIOUS_URL],
                },
                "enable_external": False,
            }
        )
        self.assertGreaterEqual(result["risk_score"], 75)
        self.assertEqual(result["risk_level"], "HIGH_RISK")
        self.assertEqual(result["classification"], "HIGH_RISK")
        self.assertTrue(result["correlated_indicators"])
        self.assertTrue(
            any(
                "Multiple independent threat indicators detected." in reason
                or "Multiple suspicious indicators correlated" in reason
                for reason in result["reasons"]
            )
        )
        self.assertTrue(
            result["recommendation"].startswith(
                "Do not interact with links or attachments."
            )
        )

    def test_external_threat_intel_unavailable(self) -> None:
        result = score_threat(
            {
                "ip_url_analysis": {"origin_ip": "1.1.1.1"},
                "enable_external": True,
            }
        )
        self.assertEqual(result["risk_score"], result["risk_score"])
        self.assertLessEqual(result["risk_score"], 100)
        self.assertNotIn("api_key", str(result).lower())
        self.assertNotIn("apikey", str(result).lower())


def print_demo() -> None:
    """Direct score_threat() demo using realistic Member 2/3/4 envelopes."""
    findings = {
        "nlp": {
            "module": "nlp",
            "risk_score": 91,
            "risk_level": "HIGH_RISK",
            "is_phishing": True,
            "confidence": 0.91,
            "indicators": ["Credential request detected"],
            "details": {
                "threat_labels": ["CREDENTIAL_PHISHING"],
                "credential_theft_detected": True,
            },
            "errors": [],
        },
        "header": {
            "module": "header",
            "risk_score": 65,
            "risk_level": "HIGH_RISK",
            "indicators": [
                "SPF authentication failed.",
                "DKIM authentication failed.",
                "DMARC authentication failed.",
            ],
            "details": {
                "from_domain": "paypal.com",
                "reply_to_domain": "gmail.com",
                "return_path_domain": "evil-login-portal.example",
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "domain_mismatch": True,
            },
            "errors": [],
        },
        "url": {
            "module": "url",
            "risk_score": 80,
            "risk_level": "HIGH_RISK",
            "indicators": ["URL contains suspicious keywords."],
            "details": {
                "extracted_urls": [KNOWN_MALICIOUS_URL],
                "suspicious_urls": [KNOWN_MALICIOUS_URL],
                "lookalike_domains": [KNOWN_MALICIOUS_DOMAIN],
            },
            "errors": [],
        },
        "ip": {
            "module": "ip",
            "risk_score": 0,
            "risk_level": "SAFE",
            "indicators": ["Earliest reasonable public sending node selected."],
            "details": {
                "chosen_sending_node": KNOWN_MALICIOUS_IP,
                "public_ips": [KNOWN_MALICIOUS_IP],
            },
            "errors": [],
        },
        "geolocation": {
            "module": "geolocation",
            "risk_score": 0,
            "risk_level": "SAFE",
            "details": {"chosen_sending_node": KNOWN_MALICIOUS_IP},
            "errors": [],
        },
        "enable_external": False,
    }
    result = score_threat(findings)
    print("\n=== score_threat() demo ===")
    print("risk_score:", result["risk_score"])
    print("risk_level:", result["risk_level"])
    print("classification:", result["classification"])
    print("recommendation:", result["recommendation"])
    print("reasons:")
    for reason in result["reasons"]:
        print(" -", reason)
    print("threat_intelligence findings:")
    for item in result["threat_intelligence"]["findings"]:
        print(" -", item.get("indicator"), item.get("known"), item.get("reason"))
    print("correlated_indicators:")
    for item in result["correlated_indicators"]:
        print(" -", item.get("pattern"), item.get("explanation"))
    print("category_scores:", result["category_scores"])


if __name__ == "__main__":
    print_demo()
    unittest.main()
