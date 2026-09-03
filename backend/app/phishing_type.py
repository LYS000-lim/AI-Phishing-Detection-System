def detect_phishing_type(url: str, features: dict) -> dict:
    """
    Classify phishing URL into 5 attack categories:

    1. Credential Theft
    2. Financial Scam
    3. Domain Spoofing / Brand Impersonation
    4. Fake Giveaway / Scam
    5. Tech Support / Malware Scam
    """

    url_lower = url.lower()

    reasons = []


    # =========================================================
    # 1. Credential Theft
    # =========================================================

    credential_keywords = [
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "password",
        "account",
        "auth",
        "authenticate",
        "secure-login"
    ]

    credential_score = 0

    for keyword in credential_keywords:
        if keyword in url_lower:
            credential_score += 1
            reasons.append(
                f"Contains credential keyword: {keyword}"
            )


    if features["NoOfSubDomain"] >= 3:
        credential_score += 1
        reasons.append(
            "Multiple subdomains detected"
        )


    if credential_score >= 2:
        return {
            "category": "Credential Theft",
            "reason": reasons
        }



    # =========================================================
    # 2. Financial Scam
    # =========================================================

    financial_keywords = [
        "bank",
        "paypal",
        "payment",
        "invoice",
        "billing",
        "wallet",
        "transaction",
        "money"
    ]

    for keyword in financial_keywords:
        if keyword in url_lower:
            reasons.append(
                f"Contains financial keyword: {keyword}"
            )

            return {
                "category": "Financial Scam",
                "reason": reasons
            }



    # =========================================================
    # 3. Fake Giveaway / Scam
    # =========================================================

    giveaway_keywords = [
        "free",
        "winner",
        "winning",
        "gift",
        "reward",
        "prize",
        "claim",
        "bonus"
    ]

    for keyword in giveaway_keywords:
        if keyword in url_lower:
            reasons.append(
                f"Contains giveaway keyword: {keyword}"
            )

            return {
                "category": "Fake Giveaway / Scam",
                "reason": reasons
            }



    # =========================================================
    # 4. Tech Support / Malware Scam
    # =========================================================

    malware_keywords = [
        "virus",
        "warning",
        "alert",
        "support",
        "update",
        "download",
        "install",
        ".exe",
        "crack"
    ]

    for keyword in malware_keywords:
        if keyword in url_lower:
            reasons.append(
                f"Contains malware/support keyword: {keyword}"
            )

            return {
                "category": "Tech Support / Malware Scam",
                "reason": reasons
            }



    # =========================================================
    # 5. Domain Spoofing / Brand Impersonation
    # =========================================================

    if features["IsDomainIP"] == 1:
        reasons.append(
            "Website uses IP address instead of domain name"
        )

        return {
            "category": "Domain Spoofing / Brand Impersonation",
            "reason": reasons
        }


    if features["HasObfuscation"] == 1:
        reasons.append(
            "URL contains obfuscation patterns"
        )

        return {
            "category": "Domain Spoofing / Brand Impersonation",
            "reason": reasons
        }


    if features["NoOfOtherSpecialCharsInURL"] >= 5:
        reasons.append(
            "High number of suspicious special characters"
        )

        return {
            "category": "Domain Spoofing / Brand Impersonation",
            "reason": reasons
        }



    # =========================================================
    # Default
    # =========================================================

    return {
        "category": "Domain Spoofing / Brand Impersonation",
        "reason": [
            "Detected as phishing by machine learning model",
            "No specific attack pattern identified"
        ]
    }