"""NLP phishing and social-engineering analyzer with semantic RAG support.

The public API is intentionally preserved as ``analyze_social_engineering``.

The analyzer combines:
1. Rule-based lexical detection
2. Sentence-transformer embeddings
3. ChromaDB RAG threat knowledge
4. Calibrated risk scoring
"""

from __future__ import annotations

import re
from typing import Any

from app.services.embedding_service import generate_embedding
from app.services.rag_service import search_knowledge


MODULE_NAME = "nlp"
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


# ---------------------------------------------------------------------------
# LEXICAL SCORING
# ---------------------------------------------------------------------------

CATEGORY_SCORES = {
    "urgency": {"base": 12, "step": 4, "cap": 20},
    "threat": {"base": 12, "step": 4, "cap": 20},
    "credential_theft": {"base": 22, "step": 8, "cap": 35},
    "financial_fraud": {"base": 15, "step": 6, "cap": 25},
    "malware_delivery": {"base": 25, "step": 8, "cap": 35},
    "suspicious_link": {"base": 18, "step": 6, "cap": 25},
    "data_theft": {"base": 20, "step": 6, "cap": 30},
    "social_engineering": {"base": 12, "step": 4, "cap": 20},
    "impersonation": {"base": 10, "step": 5, "cap": 15},
}


COMBO_BONUS_CAP = 20
COMBO_URGENCY_THREAT = 10
COMBO_URGENCY_CREDENTIAL = 8
COMBO_THREAT_CREDENTIAL = 8
COMBO_SOCIAL_FINANCIAL = 6
COMBO_IMPERSONATION_THEFT = 6
COMBO_MALWARE_URGENCY = 8
COMBO_LINK_CREDENTIAL = 8

UPPERCASE_BONUS = 5
UPPERCASE_MIN_LETTERS = 12
UPPERCASE_RATIO = 0.40


# ---------------------------------------------------------------------------
# PATTERNS
# ---------------------------------------------------------------------------

URGENCY_PATTERNS = [
    "urgent",
    "urgently",
    "immediately",
    "act now",
    "action required",
    "final warning",
    "limited time",
    "respond now",
    "within 24 hours",
    "without delay",
    "time sensitive",
    "expires today",
    "do this today",
    "last chance",
    "claim your reward now",
]


THREAT_PATTERNS = [
    "account suspended",
    "account will be suspended",
    "account blocked",
    "account will be closed",
    "account closed",
    "account closure",
    "legal action",
    "security breach",
    "unauthorized activity",
    "access will be terminated",
    "losing access",
    "lose access",
    "account locked",
    "account compromised",
    "service will be terminated",
]


CREDENTIAL_PATTERNS = [
    "verify your password",
    "enter your password",
    "confirm your password",
    "confirm credentials",
    "confirm your credentials",
    "verify your account",
    "login to your account",
    "log in to your account",
    "update your credentials",
    "reset your password",
    "validate your password",
    "verify your identity",
    "enter the verification code",
    "verify your mfa",
    "confirm your login details",
    "login details",
    "account credentials",
]


FINANCIAL_PATTERNS = [
    "payment required",
    "payment failed",
    "transfer money",
    "transfer the amount",
    "transfer outstanding amount",
    "outstanding amount",
    "bank verification",
    "confirm your bank details",
    "invoice payment",
    "wire transfer",
    "send payment",
    "send money",
    "bank account details",
    "complete the payment",
    "send the funds",
    "transfer the funds",
    "new bank details",
    "payment instructions",
    "make a payment",
    "transfer the outstanding amount",
]


MALWARE_PATTERNS = [
    "malicious attachment",
    "infected attachment",
    "download the attachment",
    "open the attachment",
    "download and open",
    "enable macros",
    "enable content",
    "install the software",
    "install the required software",
    "invoice is attached",
    "document is attached",
    "download the document",
    "open the document",
    "run the attachment",
]


SUSPICIOUS_LINK_PATTERNS = [
    "click this link",
    "click the link",
    "click here",
    "verify using the link",
    "use the link below",
    "link below",
    "verification link",
    "login link",
    "confirm your login",
    "click the url",
    "open this link",
]


DATA_THEFT_PATTERNS = [
    "confidential customer database",
    "customer database",
    "employee information",
    "employee data",
    "confidential data",
    "confidential information",
    "sensitive information",
    "sensitive data",
    "send me the database",
    "send the database",
    "export the database",
    "download the database",
    "share the customer data",
    "send customer data",
    "company data",
]


SOCIAL_ENGINEERING_PATTERNS = [
    "confidential",
    "do not tell anyone",
    "keep this secret",
    "keep this confidential",
    "bypass normal procedures",
    "urgent request from your manager",
    "unusual request",
    "do not share this",
    "between us",
    "handle this privately",
    "do not discuss this",
]


IMPERSONATION_PATTERNS = [
    "your bank",
    "from the bank",
    "bank security",
    "government",
    "tax authority",
    "security team",
    "it support",
    "it department",
    "system administrator",
    "your administrator",
    "help desk",
    "official notice",
]


CATEGORY_PATTERNS: dict[str, list[str]] = {
    "urgency": URGENCY_PATTERNS,
    "threat": THREAT_PATTERNS,
    "credential_theft": CREDENTIAL_PATTERNS,
    "financial_fraud": FINANCIAL_PATTERNS,
    "malware_delivery": MALWARE_PATTERNS,
    "suspicious_link": SUSPICIOUS_LINK_PATTERNS,
    "data_theft": DATA_THEFT_PATTERNS,
    "social_engineering": SOCIAL_ENGINEERING_PATTERNS,
    "impersonation": IMPERSONATION_PATTERNS,
}


INDICATOR_LABELS = {
    "urgency": "Urgency language detected",
    "threat": "Account suspension threat detected",
    "credential_theft": "Credential request detected",
    "financial_fraud": "Financial payment request detected",
    "malware_delivery": "Malware delivery indicator detected",
    "suspicious_link": "Suspicious link indicator detected",
    "data_theft": "Sensitive data request detected",
    "social_engineering": "Social engineering secrecy language detected",
    "impersonation": "Possible organizational impersonation language detected",
}


THREAT_LABELS = {
    "urgency": "URGENCY_TIME_PRESSURE",
    "threat": "FEAR_MANIPULATION",
    "credential_theft": "CREDENTIAL_PHISHING",
    "financial_fraud": "FINANCIAL_FRAUD",
    "malware_delivery": "MALWARE_DELIVERY",
    "suspicious_link": "SUSPICIOUS_LINK",
    "data_theft": "DATA_THEFT",
    "social_engineering": "SOCIAL_ENGINEERING",
    "impersonation": "BANK_IMPERSONATION",
}


# ---------------------------------------------------------------------------
# RAG / SEMANTIC CONFIGURATION
# ---------------------------------------------------------------------------

SEMANTIC_LABEL_THRESHOLD = 0.50
STRONG_MATCH_THRESHOLD = 0.55
MODERATE_MATCH_THRESHOLD = 0.45
RAG_RESULT_LIMIT = 5


ATTACK_WEIGHTS = {
    "CREDENTIAL_PHISHING": 20,
    "ACCOUNT_TAKEOVER": 20,
    "BUSINESS_EMAIL_COMPROMISE": 20,
    "CEO_IMPERSONATION": 20,
    "FINANCIAL_FRAUD": 20,
    "INVOICE_FRAUD": 19,
    "BANK_IMPERSONATION": 19,
    "GOVERNMENT_IMPERSONATION": 18,
    "SOCIAL_ENGINEERING": 12,
    "URGENCY_TIME_PRESSURE": 10,
    "FEAR_MANIPULATION": 18,
    "MALWARE_DELIVERY": 25,
    "SUSPICIOUS_LINK": 18,
    "GIFT_CARD_SCAM": 22,
    "DATA_THEFT": 20,
}


# ---------------------------------------------------------------------------
# REGEX PREPARATION
# ---------------------------------------------------------------------------

_PATTERN_REGEX: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    category: [
        (
            phrase,
            re.compile(
                r"\b" + re.escape(phrase) + r"\b",
                re.IGNORECASE,
            ),
        )
        for phrase in phrases
    ]
    for category, phrases in CATEGORY_PATTERNS.items()
}


# ---------------------------------------------------------------------------
# BASIC HELPERS
# ---------------------------------------------------------------------------

def _empty_envelope(errors: list[str] | None = None) -> dict[str, Any]:
    """Return a safe empty NLP module response."""

    return {
        "module": MODULE_NAME,
        "risk_score": 0,
        "risk_level": "SAFE",
        "indicators": [],
        "details": {
            "threat_labels": [],
            "semantic_analysis": {
                "enabled": False,
                "model": MODEL_NAME,
                "confidence": 0.0,
            },
            "rag_matches": [],
            "urgency_detected": False,
            "threat_detected": False,
            "credential_theft_detected": False,
            "financial_fraud_detected": False,
            "malware_delivery_detected": False,
            "suspicious_link_detected": False,
            "data_theft_detected": False,
            "social_engineering_detected": False,
            "impersonation_detected": False,
            "matched_patterns": {},
        },
        "errors": errors or [],
    }


def _risk_level(score: int) -> str:
    """Convert numerical risk score to project risk level."""

    if score <= 30:
        return "SAFE"

    if score <= 60:
        return "SUSPICIOUS"

    return "HIGH_RISK"


def _category_points(
    unique_hits: int,
    spec: dict[str, int],
) -> int:
    """Calculate capped points for lexical category matches."""

    if unique_hits <= 0:
        return 0

    return min(
        spec["cap"],
        spec["base"] + (unique_hits - 1) * spec["step"],
    )


def _find_unique_matches(
    text: str,
    category: str,
) -> list[str]:
    """Find unique lexical phrases for a category."""

    found: list[str] = []
    seen: set[str] = set()

    for phrase, regex in _PATTERN_REGEX[category]:
        if regex.search(text) and phrase not in seen:
            seen.add(phrase)
            found.append(phrase)

    return found


def _uppercase_shouting(text: str) -> bool:
    """Detect excessive uppercase text."""

    letters = [ch for ch in text if ch.isalpha()]

    if len(letters) < UPPERCASE_MIN_LETTERS:
        return False

    uppercase_count = sum(
        1 for ch in letters if ch.isupper()
    )

    return (
        uppercase_count / len(letters)
    ) >= UPPERCASE_RATIO


def _combination_bonus(
    detected: dict[str, bool],
) -> int:
    """Add additional points when dangerous lexical signals combine."""

    bonus = 0

    if detected["urgency"] and detected["threat"]:
        bonus += COMBO_URGENCY_THREAT

    if detected["urgency"] and detected["credential_theft"]:
        bonus += COMBO_URGENCY_CREDENTIAL

    if detected["threat"] and detected["credential_theft"]:
        bonus += COMBO_THREAT_CREDENTIAL

    if detected["social_engineering"] and detected["financial_fraud"]:
        bonus += COMBO_SOCIAL_FINANCIAL

    if detected["impersonation"] and (
        detected["credential_theft"]
        or detected["financial_fraud"]
    ):
        bonus += COMBO_IMPERSONATION_THEFT

    if detected["malware_delivery"] and detected["urgency"]:
        bonus += COMBO_MALWARE_URGENCY

    if detected["suspicious_link"] and detected["credential_theft"]:
        bonus += COMBO_LINK_CREDENTIAL

    return min(COMBO_BONUS_CAP, bonus)


# ---------------------------------------------------------------------------
# ATTACK TYPE MAPPING
# ---------------------------------------------------------------------------

def _map_attack_type_to_label(
    attack_type: str,
) -> str:
    """Normalize RAG attack types to stable project labels."""

    normalized = (
        str(attack_type)
        .strip()
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )

    mapping = {
        "CREDENTIAL_PHISHING": "CREDENTIAL_PHISHING",
        "ACCOUNT_TAKEOVER": "ACCOUNT_TAKEOVER",
        "BUSINESS_EMAIL_COMPROMISE": "BUSINESS_EMAIL_COMPROMISE",
        "CEO_IMPERSONATION": "CEO_IMPERSONATION",
        "FINANCIAL_FRAUD": "FINANCIAL_FRAUD",
        "INVOICE_FRAUD": "INVOICE_FRAUD",
        "BANK_IMPERSONATION": "BANK_IMPERSONATION",
        "GOVERNMENT_IMPERSONATION": "GOVERNMENT_IMPERSONATION",
        "SOCIAL_ENGINEERING": "SOCIAL_ENGINEERING",
        "URGENCY_TIME_PRESSURE": "URGENCY_TIME_PRESSURE",
        "FEAR_MANIPULATION": "FEAR_MANIPULATION",
        "MALWARE_DELIVERY": "MALWARE_DELIVERY",
        "SUSPICIOUS_LINK": "SUSPICIOUS_LINK",
        "GIFT_CARD_SCAM": "GIFT_CARD_SCAM",
        "DATA_THEFT": "DATA_THEFT",
    }

    return mapping.get(normalized, normalized)


# ---------------------------------------------------------------------------
# SEMANTIC SCORE
# ---------------------------------------------------------------------------

def _semantic_match_score(
    rag_matches: list[dict[str, Any]],
    detected: dict[str, bool],
) -> tuple[int, str | None]:
    """Calculate calibrated semantic risk contribution."""

    if not rag_matches:
        return 0, None

    scored_matches: list[tuple[str, float]] = []

    for match in rag_matches:
        attack_type = _map_attack_type_to_label(
            match.get("attack_type", "UNKNOWN")
        )

        similarity = float(
            match.get("similarity", 0.0)
        )

        if similarity < MODERATE_MATCH_THRESHOLD:
            continue

        scored_matches.append(
            (attack_type, similarity)
        )

    if not scored_matches:
        return 0, None

    scored_matches.sort(
        key=lambda item: item[1],
        reverse=True,
    )

    strongest_attack, strongest_similarity = scored_matches[0]

    if strongest_similarity >= STRONG_MATCH_THRESHOLD:
        confidence_factor = min(
            1.0,
            max(
                0.0,
                (strongest_similarity - STRONG_MATCH_THRESHOLD) / 0.25,
            ),
        )

        base_score = 22 + int(
            round(confidence_factor * 10)
        )
    else:
        confidence_factor = (
            strongest_similarity - MODERATE_MATCH_THRESHOLD
        ) / (
            STRONG_MATCH_THRESHOLD - MODERATE_MATCH_THRESHOLD
        )

        base_score = 10 + int(
            round(max(0.0, confidence_factor) * 10)
        )

    attack_weight = ATTACK_WEIGHTS.get(
        strongest_attack,
        12,
    )

    semantic_score = max(
        base_score,
        int(round(attack_weight * 0.75)),
    )

    for attack_type, similarity in scored_matches[1:]:
        if (
            similarity >= STRONG_MATCH_THRESHOLD
            and attack_type != strongest_attack
        ):
            semantic_score += 5
            break

    if strongest_attack == "MALWARE_DELIVERY":
        if detected["urgency"]:
            semantic_score += 12
        if detected["threat"]:
            semantic_score += 8

    if strongest_attack in {
        "CREDENTIAL_PHISHING",
        "ACCOUNT_TAKEOVER",
    }:
        if detected["urgency"]:
            semantic_score += 10
        if detected["threat"]:
            semantic_score += 8

    if strongest_attack in {
        "GIFT_CARD_SCAM",
        "FINANCIAL_FRAUD",
        "INVOICE_FRAUD",
        "BUSINESS_EMAIL_COMPROMISE",
        "CEO_IMPERSONATION",
    }:
        if detected["urgency"]:
            semantic_score += 8

    if strongest_attack == "DATA_THEFT":
        if detected["urgency"]:
            semantic_score += 8

    if strongest_attack == "SUSPICIOUS_LINK":
        if detected["credential_theft"]:
            semantic_score += 8

    semantic_score = min(
        55,
        max(0, semantic_score),
    )

    return semantic_score, strongest_attack


# ---------------------------------------------------------------------------
# MAIN ANALYZER
# ---------------------------------------------------------------------------

def analyze_social_engineering(
    email_text: str | None,
) -> dict[str, Any]:
    """Analyze email text using lexical detection and semantic RAG."""

    if email_text is None or not str(email_text).strip():
        return _empty_envelope(
            ["No analyzable text was provided."]
        )

    text = str(email_text).strip()

    matched_patterns: dict[str, list[str]] = {}
    category_points: dict[str, int] = {}
    lexical_labels: set[str] = set()
    errors: list[str] = []

    # ---------------------------------------------------------------
    # 1. Rule-based / lexical analysis
    # ---------------------------------------------------------------

    for category in CATEGORY_PATTERNS:
        hits = _find_unique_matches(
            text,
            category,
        )

        if hits:
            matched_patterns[category] = hits

            lexical_labels.add(
                THREAT_LABELS.get(
                    category,
                    category.upper(),
                )
            )

        category_points[category] = _category_points(
            len(hits),
            CATEGORY_SCORES[category],
        )

    detected = {
        name: bool(
            matched_patterns.get(name)
        )
        for name in CATEGORY_PATTERNS
    }

    lexical_score = sum(
        category_points.values()
    )

    lexical_score += _combination_bonus(
        detected
    )

    if _uppercase_shouting(text):
        lexical_score += UPPERCASE_BONUS

    lexical_score = min(
        100,
        max(0, int(lexical_score)),
    )

    # ---------------------------------------------------------------
    # 2. Response details
    # ---------------------------------------------------------------

    details: dict[str, Any] = {
        "threat_labels": sorted(
            lexical_labels
        ),
        "semantic_analysis": {
            "enabled": False,
            "model": MODEL_NAME,
            "confidence": 0.0,
        },
        "rag_matches": [],
        "urgency_detected": detected["urgency"],
        "threat_detected": detected["threat"],
        "credential_theft_detected": detected["credential_theft"],
        "financial_fraud_detected": detected["financial_fraud"],
        "malware_delivery_detected": detected["malware_delivery"],
        "suspicious_link_detected": detected["suspicious_link"],
        "data_theft_detected": detected["data_theft"],
        "social_engineering_detected": detected["social_engineering"],
        "impersonation_detected": detected["impersonation"],
        "matched_patterns": matched_patterns,
    }

    # ---------------------------------------------------------------
    # 3. Semantic embedding + RAG
    # ---------------------------------------------------------------

    semantic_result = generate_embedding(text)

    if not semantic_result.get("ok"):
        errors.append(
            str(
                semantic_result.get(
                    "error",
                    "Embedding model unavailable.",
                )
            )
        )
    else:
        try:
            rag_matches = search_knowledge(
                text,
                limit=RAG_RESULT_LIMIT,
                min_similarity=MODERATE_MATCH_THRESHOLD,
            )

            details["rag_matches"] = [
                {
                    "attack_type": match.get(
                        "attack_type",
                        "unknown",
                    ),
                    "similarity": round(
                        float(
                            match.get(
                                "similarity",
                                0.0,
                            )
                        ),
                        4,
                    ),
                    "description": match.get(
                        "description",
                        "",
                    ),
                }
                for match in rag_matches
            ]

            semantic_labels = {
                _map_attack_type_to_label(
                    match.get(
                        "attack_type",
                        "unknown",
                    )
                )
                for match in rag_matches
                if float(
                    match.get(
                        "similarity",
                        0.0,
                    )
                ) >= SEMANTIC_LABEL_THRESHOLD
            }

            details["threat_labels"] = sorted(
                set(details["threat_labels"])
                | semantic_labels
            )

            if rag_matches:
                details[
                    "semantic_analysis"
                ]["enabled"] = True

                confidence = max(
                    float(
                        match.get(
                            "similarity",
                            0.0,
                        )
                    )
                    for match in rag_matches
                )

                details[
                    "semantic_analysis"
                ]["confidence"] = round(
                    confidence,
                    4,
                )
            else:
                details[
                    "semantic_analysis"
                ]["enabled"] = True

                details[
                    "semantic_analysis"
                ]["confidence"] = 0.0

        except Exception as exc:
            errors.append(
                f"RAG analysis failed: {exc}"
            )

    # ---------------------------------------------------------------
    # 4. Human-readable indicators
    # ---------------------------------------------------------------

    indicators: list[str] = []

    for category, label in INDICATOR_LABELS.items():
        if detected[category]:
            indicators.append(label)

    if details["rag_matches"]:
        for match in details["rag_matches"][:2]:
            indicators.append(
                f"Semantic match: "
                f"{match['attack_type']}"
            )

    # ---------------------------------------------------------------
    # 5. Calibrated semantic score
    # ---------------------------------------------------------------

    semantic_score, strongest_attack = (
        _semantic_match_score(
            details["rag_matches"],
            detected,
        )
    )

    # ---------------------------------------------------------------
    # 6. Final score
    # ---------------------------------------------------------------

    score = min(
        100,
        max(
            0,
            int(
                lexical_score
                + semantic_score
            ),
        ),
    )

    # ---------------------------------------------------------------
    # 7. Safety overrides / minimums
    # ---------------------------------------------------------------

    strongest_similarity = 0.0

    if details["rag_matches"]:
        strongest_similarity = max(
            float(match.get("similarity", 0.0))
            for match in details["rag_matches"]
        )

    # Strong semantic malware match.
    if (
        strongest_attack == "MALWARE_DELIVERY"
        and strongest_similarity >= 0.50
    ):
        score = max(score, 70)

    # Strong credential/account phishing.
    if (
        strongest_attack in {
            "CREDENTIAL_PHISHING",
            "ACCOUNT_TAKEOVER",
        }
        and strongest_similarity >= 0.50
    ):
        score = max(score, 65)

    # Strong financial fraud / impersonation.
    if (
        strongest_attack in {
            "FINANCIAL_FRAUD",
            "INVOICE_FRAUD",
            "BUSINESS_EMAIL_COMPROMISE",
            "CEO_IMPERSONATION",
            "BANK_IMPERSONATION",
            "GOVERNMENT_IMPERSONATION",
            "DATA_THEFT",
        }
        and strongest_similarity >= 0.50
    ):
        score = max(score, 65)

    # Strong gift-card scam.
    if (
        strongest_attack == "GIFT_CARD_SCAM"
        and strongest_similarity >= 0.50
    ):
        score = max(score, 65)

    # Strong lexical malware delivery combined with urgency.
    if (
        detected["malware_delivery"]
        and detected["urgency"]
    ):
        score = max(score, 60)

    # Strong lexical suspicious-link + credential request.
    if (
        detected["suspicious_link"]
        and detected["credential_theft"]
    ):
        score = max(score, 55)

    # Strong lexical data-theft request.
    if detected["data_theft"]:
        score = max(score, 45)

    score = min(
        100,
        max(0, int(score)),
    )

    # ---------------------------------------------------------------
    # 8. Final response
    # ---------------------------------------------------------------

    response = {
        "module": MODULE_NAME,
        "risk_score": score,
        "risk_level": _risk_level(score),
        "indicators": indicators,
        "details": details,
        "errors": errors,
    }

    return response