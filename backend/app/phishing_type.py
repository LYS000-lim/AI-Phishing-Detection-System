from urllib.parse import urlparse


def detect_phishing_type(url: str, features: dict) -> dict:
    """
    Separate phishing attack objective from phishing techniques.

    Categories:
    1. Credential Theft
    2. Financial Scam
    3. Fake Giveaway
    4. Malware Distribution
    5. Tech Support Scam

    Techniques:
    1. Domain Spoofing
    2. Typosquatting
    3. Brand Impersonation
    4. Subdomain Abuse
    5. URL Obfuscation
    6. Shortened URL Abuse
    """

    url_lower = url.lower()

    techniques = []

    technique_evidence = []

    category_evidence = []

    # =========================================================
    # Parse URL
    # =========================================================

    try:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )
        hostname = (parsed.hostname or "").lower()

        path_text = (parsed.path or "").lower()

        query_text = (parsed.query or "").lower()

        domain_text = hostname.replace("-", "")
    except Exception:
        hostname = ""
        path_text = ""
        query_text = ""
        domain_text = ""

    # Higher risk areas:
    # domain > subdomain > path > query

    high_priority_text = (
        hostname
        + " "
        + path_text
    )

    full_url_text = (
        url_lower
    )

    # =========================================================
    # PART 1: ATTACK CATEGORY / OBJECTIVE
    # =========================================================

    # =========================================================
    # CATEGORY PRIORITY
    # Used when multiple categories receive similar scores
    # =========================================================

    category_priority = {

        "Financial Scam": 5,

        "Credential Theft": 4,

        "Malware Distribution": 3,

        "Tech Support Scam": 2,

        "Fake Giveaway": 1,

    }

    category_scores = {
        "Credential Theft": 0,
        "Financial Scam": 0,
        "Fake Giveaway": 0,
        "Malware Distribution": 0,
        "Tech Support Scam": 0,
    }

    # =========================================================
    # BRAND ALIAS DETECTION
    # Detect legitimate brands and common phishing variations
    # =========================================================

    brand_aliases = {

        "paypal": [
            "paypal",
            "paypa1",
            "pay-pal",
        ],

        "google": [
            "google",
            "goog1e",
            "g00gle",
        ],

        "microsoft": [
            "microsoft",
            "micros0ft",
        ],

        "apple": [
            "apple",
            "app1e",
        ],

        "facebook": [
            "facebook",
            "faceb00k",
        ],

        "maybank": [
            "maybank",
            "mayb4nk",
        ],

        "cimb": [
            "cimb",
        ],

        "rhb": [
            "rhb",
        ],

        "hsbc": [
            "hsbc",
        ],

    }

    category_keywords = {
        "Credential Theft": {
            "login": 3,
            "signin": 3,
            "sign-in": 3,
            "verify": 2,
            "verification": 2,
            "password": 3,
            "account": 2,
            "auth": 2,
            "authenticate": 2,
            "secure-login": 3,
        },

        "Financial Scam": {
            "bank":5,
            "paypal":3,
            "maybank":3,
            "cimb":3,
            "publicbank":5,
            "rhb":5,
            "hsbc":5,
            "payment":3,
            "invoice":2,
            "billing":2,
            "wallet":2,
            "transaction":3,
            "money":2,
            "credit":2,
            "debit":2,
        },

        "Fake Giveaway": {
            "free": 2,
            "winner": 3,
            "winning": 3,
            "gift": 2,
            "reward": 2,
            "prize": 3,
            "claim": 2,
            "bonus": 2,
        },

        "Malware Distribution": {
            "download": 3,
            "install": 3,
            ".exe": 4,
            "software": 2,
            "update-file": 3,
            "crack": 3,
            "apk": 3,
        },

        "Tech Support Scam": {
            "virus": 3,
            "warning": 2,
            "alert": 2,
            "support": 3,
            "technical-support": 3,
            "tech-support": 3,
            "computer-help": 3,
            "device-warning": 3,
        },
    }

    category_matches = {}

    # =========================================================
    # BRAND BASED CATEGORY BOOST
    # =========================================================

    brand_matches = []


    for brand, aliases in brand_aliases.items():

        for alias in aliases:

            if alias in high_priority_text:

                brand_matches.append(
                    brand
                )

                break



    # Financial brands strongly indicate
    # possible financial phishing

    for brand in brand_matches:

        if brand in [
            "paypal",
            "maybank",
            "cimb",
            "rhb",
            "hsbc",
        ]:

            category_scores["Financial Scam"] += 10

    # =========================================================
    # BRAND + ACTION COMBINATION
    # Strong phishing indicator
    # =========================================================

    suspicious_actions = [

        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "confirm",
        "password",

    ]


    action_matches = [
        action
        for action in suspicious_actions
        if action in full_url_text
    ]


    if brand_matches and action_matches:

        category_scores["Credential Theft"] += 15


        # Financial brands + account actions
        # usually indicate financial phishing

        if any(
            brand in [
                "paypal",
                "maybank",
                "cimb",
                "rhb",
                "hsbc",
            ]
            for brand in brand_matches
        ):

            category_scores["Financial Scam"] += 15


        if any(
            brand in [
                "paypal",
                "maybank",
                "cimb",
                "rhb",
                "hsbc",
            ]
            for brand in brand_matches
        ):

            category_scores["Financial Scam"] += 10

    for category_name, keywords in category_keywords.items():
        matches = []

        for word, weight in keywords.items():
            if word in high_priority_text:
                category_scores[category_name] += weight
                matches.append(word)

        category_matches[category_name] = matches

    # =========================================================
    # Select best category
    # Score first, priority second
    # =========================================================

    best_category = max(
        category_scores,
        key=lambda category: (
            category_scores[category],
            category_priority[category]
        )
    )

    max_score = category_scores[best_category]

    total_score = sum(category_scores.values())


    if max_score > 0:
        category_confidence  = int(
            (max_score / total_score) * 100
        )
    else:
        category_confidence  = 0

    if category_scores[best_category] > 0:

        category = best_category

        matched_keywords = category_matches[best_category]


        if category == "Financial Scam":

            detected_brand = (
                brand_matches[0]
                if brand_matches
                else "financial service"
            )


            evidence = (
                f"The URL contains a financial brand indicator "
                f"related to \"{detected_brand.title()}\" "
                "combined with suspicious URL patterns, "
                "which may indicate a financial phishing attempt."
            )


        elif category == "Credential Theft":

            evidence = (
                "The URL contains account-related wording "
                "that may indicate an attempt to collect "
                "user credentials."
            )


        elif category == "Fake Giveaway":

            evidence = (
                "The URL contains promotional wording such as "
                "prize, reward, or winner-related terms commonly "
                "used in fake giveaway scams."
            )


        elif category == "Malware Distribution":

            evidence = (
                "The URL contains download or software-related "
                "keywords that may indicate malware distribution."
            )


        elif category == "Tech Support Scam":

            evidence = (
                "The URL contains technical warning or support "
                "keywords commonly associated with fake support scams."
            )


        category_evidence.append({

            "category": category,

            "evidence": evidence

        })


    else:

        category = "Unknown / Other Phishing"

        category_evidence.append({

            "category": category,

            "evidence": (
                "No strong attack-objective pattern was identified "
                "from the URL."
            )

        })

    # =========================================================
    # PART 2: ATTACK TECHNIQUES
    # =========================================================

    # ---------------------------------------------------------
    # URL Obfuscation
    # ---------------------------------------------------------

    if features.get("HasObfuscation", 0) == 1:
        techniques.append("URL Obfuscation")

        technique_evidence.append({
            "technique": "URL Obfuscation",
            "evidence": (
                "Encoded or hidden characters were detected in the URL."
            ),
        })

    # ---------------------------------------------------------
    # Subdomain Abuse
    # ---------------------------------------------------------

    subdomains = features.get("NoOfSubDomain", 0)

    if subdomains >= 3:
        techniques.append("Subdomain Abuse")

        technique_evidence.append({
            "technique": "Subdomain Abuse",
            "evidence": (
                f"The URL contains {subdomains} subdomains, creating "
                "a complex domain structure."
            ),
        })

    # ---------------------------------------------------------
    # Domain Spoofing
    # ---------------------------------------------------------

    if features.get("IsDomainIP", 0) == 1:
        techniques.append("Domain Spoofing")

        technique_evidence.append({
            "technique": "Domain Spoofing",
            "evidence": (
                "An IP address is used instead of a normal domain name."
            ),
        })

    # ---------------------------------------------------------
    # Shortened URL Abuse
    # ---------------------------------------------------------

    shortened_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "cutt.ly",
        "tiny.cc",
        "rebrand.ly",
    ]

    if any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in shortened_domains
    ):
        techniques.append("Shortened URL Abuse")

        technique_evidence.append({
            "technique": "Shortened URL Abuse",
            "evidence": (
                f"The URL uses the shortening service '{hostname}', "
                "which can hide the final destination."
            ),
        })

    # ---------------------------------------------------------
    # Brand Impersonation
    # ---------------------------------------------------------

    trusted_brands = [
        "paypal",
        "google",
        "microsoft",
        "apple",
        "amazon",
        "facebook",
        "instagram",
        "netflix",

        # financial brands
        "maybank",
        "cimb",
        "publicbank",
        "rhb",
        "hsbc",
    ]

    suspicious_words = [
        "login",
        "secure",
        "verify",
        "verification",
        "account",
        "update",
        "payment",
        "support",
        "confirm",
    ]

    for brand in trusted_brands:
        if brand in domain_text:

            matched_suspicious_words = [
                word
                for word in suspicious_words
                if word in url_lower
            ]

            if matched_suspicious_words:
                techniques.append("Brand Impersonation")

                technique_evidence.append({

                    "technique": "Brand Impersonation",

                    "evidence":
                    (
                        f"The brand name \"{brand.title()}\" appears "
                        "together with suspicious wording such as "
                        f"\"{matched_suspicious_words[0]}\"."
                    )

                })

                break

    # ---------------------------------------------------------
    # Typosquatting
    # ---------------------------------------------------------

    suspicious_brand_patterns = {
        "paypal": [
            "paypa1",
            "pay-pal",
        ],
        "google": [
            "goog1e",
            "g00gle",
        ],
        "microsoft": [
            "micros0ft",
        ],
        "apple": [
            "app1e",
        ],
        "facebook": [
            "faceb00k",
            "face-book",
        ],
    }

    for brand, patterns in suspicious_brand_patterns.items():

        matched = False

        for pattern in patterns:
            if pattern in domain_text:
                techniques.append("Typosquatting")

                technique_evidence.append({
                    "technique": "Typosquatting",
                    "evidence": (
                        f"The text '{pattern}' appears similar to "
                        f"the trusted brand '{brand}'."
                    ),
                })

                matched = True
                break

        if matched:
            break

    # =========================================================
    # Remove duplicate technique evidence
    # =========================================================

    unique_evidence = []

    seen = set()


    for item in technique_evidence:

        key = item["technique"]

        if key not in seen:

            unique_evidence.append(item)

            seen.add(key)


    technique_evidence = unique_evidence
    
    # =========================================================
    # FALLBACK TECHNIQUE
    # =========================================================

    techniques = list(dict.fromkeys(techniques))

    if not techniques:
        techniques = ["Unknown / Unclassified Technique"]

        technique_evidence.append({
            "technique": "Unknown / Unclassified Technique",
            "evidence": (
                "No specific phishing technique was confidently "
                "identified from the available URL information."
            ),
        })

    # =========================================================
    # PART 3: FINAL PHISHING CONFIDENCE ENGINE
    # =========================================================

    # Number of detected techniques
    technique_count = len(
        techniques
    )

    technique_scores = {

        "Brand Impersonation": 25,

        "Typosquatting": 20,

        "Domain Spoofing": 20,

        "Shortened URL Abuse": 15,

        "URL Obfuscation": 15,

        "Subdomain Abuse": 10,

        "Unknown / Unclassified Technique": 0,
        }


    technique_score = sum(
        technique_scores.get(
            technique,
            0
        )
        for technique in techniques
    )


    # Bonus confidence when multiple independent
    # techniques support the same conclusion.

    if technique_count >= 3:

        technique_score += 10

    elif technique_count >= 2:

        technique_score += 5

    # =========================================================
    # KEYWORD CONFIDENCE CALCULATION
    # =========================================================

    keyword_score = min(
        max_score * 5,
        40
    )


    # Reduce confidence when only weak keywords exist

    if max_score <= 2 and not brand_matches:

        keyword_score = min(
            keyword_score,
            10
        )


    # Extra confidence when a known brand
    # is combined with suspicious actions

    if brand_matches and action_matches:

        keyword_score += 15


    keyword_score = min(
        keyword_score,
        50
    )

    confidence = min(
        100,
        keyword_score + technique_score
    )

    # =========================================================
    # RULE CONFIDENCE
    # Shows how strong the rule-based detection evidence is
    # =========================================================

    if confidence >= 80:

        rule_confidence = "High"

    elif confidence >= 50:

        rule_confidence = "Medium"

    elif confidence > 0:

        rule_confidence = "Low"

    else:

        rule_confidence = "None"

    risk_level = "Unknown"

    if confidence >= 80:

        risk_level = "High"

    elif confidence >= 50:

        risk_level = "Medium"

    elif confidence > 0:

        risk_level = "Low"

    else:

        risk_level = "Unknown"

    # =========================================================
    # FINAL RESULT
    # =========================================================

    if len(category_evidence) > 0:

        evidence_strength = (
            "Strong"
            if confidence >= 80
            else
            "Moderate"
            if confidence >= 50
            else
            "Weak"
        )

    else:

        evidence_strength = "None"

    # =========================================================
    # Human readable detection summary
    # =========================================================

    summary = (
        f"Detected {category} pattern "
        f"with {rule_confidence.lower()} confidence."
    )

    return {
        "category": category,

        "confidence": confidence,

        "rule_confidence": rule_confidence,

        "category_confidence": category_confidence,

        "risk_level": risk_level,

        "techniques": techniques,

        "category_evidence": category_evidence,

        "technique_evidence": technique_evidence,

        "evidence_strength": evidence_strength,

        "summary": summary,
    }