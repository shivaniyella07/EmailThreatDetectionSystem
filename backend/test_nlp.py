from app.services.nlp_analyzer import analyze_social_engineering

tests = {
    "Credential Phishing":
        "Your account will be suspended. Verify your password immediately using the link below.",

    "Account Takeover":
        "We detected a suspicious login. Confirm your account credentials immediately to prevent unauthorized access.",

    "Financial Fraud":
        "Your payment has failed. Please transfer the outstanding amount immediately to avoid account closure.",

    "Malware Delivery":
        "Your invoice is attached. Download and open the document immediately to install the required software.",

    "CEO Impersonation":
        "Hi, I am your CEO. I am in a meeting and need you to purchase gift cards immediately and send me the codes.",

    "Gift Card Scam":
        "Congratulations! You have won a gift card. Claim your reward now.",

    "Suspicious Link":
        "Your account requires verification. Click this link to confirm your login details.",

    "Data Theft":
        "Please send me the company's confidential customer database and employee information immediately."
}

print("\n" + "=" * 90)
print("              EMAIL THREAT DETECTION - NLP TEST")
print("=" * 90)

for name, text in tests.items():
    result = analyze_social_engineering(text)

    details = result.get("details", {})
    semantic = details.get("semantic_analysis", {})
    matches = details.get("rag_matches", [])

    print(f"\n{name}")
    print("-" * 90)
    print(f"Risk Score    : {result.get('risk_score')}")
    print(f"Risk Level    : {result.get('risk_level')}")
    print(f"Threat Labels : {details.get('threat_labels')}")
    print(f"Confidence    : {semantic.get('confidence')}")

    if matches:
        print("RAG Matches   :")
        for match in matches[:3]:
            print(
                f"  - {match.get('attack_type')} "
                f"(similarity={match.get('similarity')})"
            )
    else:
        print("RAG Matches   : None")

print("\n" + "=" * 90)
print("                         TEST COMPLETE")
print("=" * 90)