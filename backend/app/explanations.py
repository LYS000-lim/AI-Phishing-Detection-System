from typing import Iterable
from .phishing_type import detect_phishing_type

# Friendly names used when showing technical XAI information.
FRIENDLY_NAMES = {
    "URLLength": "URL length",
    "DomainLength": "domain length",
    "IsDomainIP": "IP-based domain",
    "TLDLegitimateProb": "top-level domain reputation",
    "URLCharProb": "URL character pattern",
    "TLDLength": "top-level domain length",
    "NoOfSubDomain": "number of subdomains",
    "HasObfuscation": "URL obfuscation",
    "NoOfObfuscatedChar": "obfuscated characters",
    "ObfuscationRatio": "obfuscation ratio",
    "NoOfLettersInURL": "number of letters",
    "LetterRatioInURL": "letter ratio",
    "NoOfDegitsInURL": "number of digits",
    "DegitRatioInURL": "digit ratio",
    "NoOfEqualsInURL": "number of '=' characters",
    "NoOfQMarkInURL": "number of '?' characters",
    "NoOfAmpersandInURL": "number of '&' characters",
    "NoOfOtherSpecialCharsInURL": "special characters",
    "SpacialCharRatioInURL": "special-character ratio",
    "IsHTTPS": "HTTPS usage",
}

FEATURE_DESCRIPTIONS = {

    "URLLength":
        "Total length of the URL",

    "DomainLength":
        "Length of the domain name",

    "IsDomainIP":
        "Whether the URL uses an IP address instead of domain",

    "TLDLegitimateProb":
        "Legitimate probability score of the top-level domain",

    "URLCharProb":
        "Unusual character pattern in the website address",

    "TLDLength":
        "Length of the top-level domain",

    "NoOfSubDomain":
        "Number of subdomains detected",

    "HasObfuscation":
        "Whether URL obfuscation patterns were detected",

    "NoOfObfuscatedChar":
        "Number of obfuscated characters",

    "ObfuscationRatio":
        "Ratio of hidden or encoded characters",

    "NoOfLettersInURL":
        "Number of letters detected in URL",

    "LetterRatioInURL":
        "Ratio of letters compared with URL length",

    "NoOfDegitsInURL":
        "Number of digits detected in URL",

    "DegitRatioInURL":
        "Ratio of digits compared with URL length",

    "NoOfEqualsInURL":
        "Number of '=' parameters",

    "NoOfQMarkInURL":
        "Number of '?' parameters",

    "NoOfAmpersandInURL":
        "Number of '&' parameters",

    "NoOfOtherSpecialCharsInURL":
        "Number of unusual special characters",

    "SpacialCharRatioInURL":
        "Ratio of special characters",

    "IsHTTPS":
        "HTTPS availability (1 = HTTPS, 0 = HTTP)",
}

FEATURE_EXPLANATIONS = {

    "URLLength": {
        "title": "The website address has a longer structure",
        "explanation": (
            "Longer URLs may sometimes be used by attackers to hide suspicious parts or make links appear more trustworthy."
        )
    },

    "DomainLength": {
        "title": "The domain name is unusually long",
        "explanation": (
            "Attackers may create long domain names to confuse users "
            "or imitate trusted websites."
        )
    },

    "IsDomainIP": {
        "title": "The website uses an IP address instead of a normal domain",
        "explanation": (
            "Some phishing websites use IP addresses instead of normal "
            "domain names to avoid recognition."
        )
    },

    "TLDLegitimateProb": {
        "title": "The domain extension shows suspicious characteristics",
        "explanation": (
            "Some phishing websites use uncommon domain extensions "
            "that are less frequently used by trusted websites."
        )
    },

    "URLCharProb": {
        "title": "The website address contains unusual character patterns",
        "explanation": (
            "The combination of letters, numbers, and symbols in this URL "
            "looks different from common website addresses."
        )
    },

    "TLDLength": {
        "title": "The domain extension length is unusual",
        "explanation": (
            "Unusual domain extensions may appear in suspicious websites."
        )
    },

    "NoOfSubDomain": {
        "title": "The website contains multiple subdomains",
        "explanation": (
            "Attackers may create complex subdomains to make fake websites "
            "look similar to trusted services."
        )
    },

    "HasObfuscation": {
        "title": "Hidden or encoded URL characters were detected",
        "explanation": (
            "Attackers may hide parts of a URL using encoding techniques "
            "to avoid detection."
        )
    },

    "NoOfObfuscatedChar": {
        "title": "The URL contains hidden characters",
        "explanation": (
            "Encoded characters may be used to disguise the actual website address."
        )
    },

    "ObfuscationRatio": {
        "title": "The URL contains a high amount of hidden characters",
        "explanation": (
            "A high level of URL encoding may indicate attempts to hide information."
        )
    },

    "NoOfLettersInURL": {
        "title": "The URL contains an unusual number of letters",
        "explanation": (
            "An unusual letter pattern may indicate a generated or suspicious URL."
        )
    },

    "LetterRatioInURL": {
        "title": "The letter pattern in the URL is unusual",
        "explanation": (
            "The ratio of letters compared with URL length may differ from normal websites."
        )
    },

    "NoOfDegitsInURL": {
        "title": "The website address contains several numbers",
        "explanation": (
            "Some phishing websites add numbers into URLs to create "
            "addresses that look similar to trusted websites."
        )
    },

    "DegitRatioInURL": {
        "title": "The URL contains a high proportion of numbers",
        "explanation": (
            "A large number ratio may indicate suspicious URL construction."
        )
    },

    "NoOfEqualsInURL": {
        "title": "The URL contains multiple parameters",
        "explanation": (
            "Excessive parameters may be used to create complicated "
            "or misleading links."
        )
    },

    "NoOfQMarkInURL": {
        "title": "The URL contains query parameters",
        "explanation": (
            "Suspicious websites may use query parameters to hide "
            "additional information."
        )
    },

    "NoOfAmpersandInURL": {
        "title": "The URL contains multiple linked parameters",
        "explanation": (
            "Many parameters can make URLs harder for users to verify."
        )
    },

    "NoOfOtherSpecialCharsInURL": {
        "title": "The URL contains unusual special characters",
        "explanation": (
            "Special characters may be used to create confusing URLs."
        )
    },

    "SpacialCharRatioInURL": {
        "title": "The URL has a high special-character ratio",
        "explanation": (
            "A high number of special characters may indicate suspicious URL structure."
        )
    },

    "IsHTTPS": {
        "title": "The website does not use a secure connection",
        "explanation": (
            "The website uses HTTP instead of HTTPS. HTTPS helps protect "
            "information exchanged between users and websites."
        )
    },

}

def risk_level(phishing_probability: float) -> str:
    """
    Convert phishing probability into a user-friendly risk level.
    """
    if phishing_probability < 0.50:
        return "Low"

    if phishing_probability < 0.80:
        return "Medium"

    return "High"


def _feature_indicators(features: dict, prediction: str) -> list[str]:
    """
    Generate human-readable indicators using ACTUAL extracted
    feature values.

    These rules do not replace the ML model. They only explain
    observable URL characteristics to the user.
    """

    indicators = []

    # =========================================================
    # PHISHING / SUSPICIOUS INDICATORS
    # =========================================================

    if prediction == "phishing":

        # IP address instead of normal domain
        if features.get("IsDomainIP", 0) == 1:
            indicators.append(
                "The website uses an IP address instead of a normal domain name."
            )

        # URL obfuscation
        if features.get("HasObfuscation", 0) == 1:
            indicators.append(
                "URL obfuscation was detected, which may be used to hide parts "
                "of the destination."
            )

        # Multiple subdomains
        subdomains = features.get("NoOfSubDomain", 0)

        if subdomains >= 3:
            indicators.append(
                f"The URL contains {subdomains} subdomains, creating a complex "
                "domain structure that may be misleading."
            )

        # High number of special characters
        special_chars = features.get(
            "NoOfOtherSpecialCharsInURL", 0
        )

        if special_chars >= 5:
            indicators.append(
                f"The URL contains {special_chars} unusual special characters."
            )

        # High special-character ratio
        special_ratio = features.get(
            "SpacialCharRatioInURL", 0
        )

        if special_ratio >= 0.10:
            indicators.append(
                "A relatively high proportion of special characters was detected."
            )

        # High digit ratio
        digit_ratio = features.get(
            "DegitRatioInURL", 0
        )

        if digit_ratio >= 0.20:
            indicators.append(
                "A relatively high proportion of digits was detected in the URL."
            )

        # Very long URL
        url_length = features.get(
            "URLLength", 0
        )

        if url_length >= 46:
            indicators.append(
                f"The URL is unusually long ({url_length} characters)."
            )

        # Very long domain
        domain_length = features.get(
            "DomainLength", 0
        )

        if domain_length >= 31:
            indicators.append(
                f"The domain name is unusually long ({domain_length} characters)."
            )

        # Uncommon / low-reputation TLD according to training lookup
        tld_probability = features.get(
            "TLDLegitimateProb", 0.5
        )

        if tld_probability < 0.30:
            indicators.append(
                "The website uses a domain extension that is less commonly associated "
                "with trusted websites."
            )

        # No HTTPS
        if features.get("IsHTTPS", 0) == 0:
            indicators.append(
                "The URL does not use HTTPS."
            )

    # =========================================================
    # LEGITIMATE / REASSURING INDICATORS
    # =========================================================

    else:

        if features.get("IsDomainIP", 0) == 0:
            indicators.append(
                "The URL uses a normal domain name rather than an IP address."
            )

        if features.get("HasObfuscation", 0) == 0:
            indicators.append(
                "No URL obfuscation was detected."
            )

        subdomains = features.get("NoOfSubDomain", 0)

        if subdomains <= 2:
            indicators.append(
                "The URL has a normal subdomain structure."
            )

        special_chars = features.get(
            "NoOfOtherSpecialCharsInURL", 0
        )

        if special_chars < 5:
            indicators.append(
                "The URL does not contain an excessive number of unusual "
                "special characters."
            )

        if features.get("IsHTTPS", 0) == 1:
            indicators.append(
                "The website uses HTTPS for an encrypted connection."
            )

    return indicators

def _xai_explanation_for_feature(
    feature: str,
    value,
    prediction: str,
) -> dict | None:
    """
    Return a user-friendly explanation only when the feature value
    gives meaningful evidence for the current URL.

    The same result is used by:
    1. Why was this detected?
    2. AI Explanation Evidence

    This keeps both sections consistent.
    """

    if prediction == "phishing":

        if feature == "IsDomainIP":
            if value == 1:
                return {
                    "title": "The website uses an IP address instead of a normal domain",
                    "explanation": (
                        "Using an IP address instead of a normal domain name "
                        "can make a website harder for users to recognise."
                    ),
                }
            return None

        if feature == "HasObfuscation":
            if value == 1:
                return {
                    "title": "Hidden or encoded URL content was detected",
                    "explanation": (
                        "Encoded or hidden parts can make the actual website "
                        "destination more difficult to inspect."
                    ),
                }
            return None

        if feature == "NoOfSubDomain":
            if value >= 3:
                return {
                    "title": f"The URL contains {value} subdomains",
                    "explanation": (
                        "A complex subdomain structure may make a suspicious "
                        "website appear more trustworthy."
                    ),
                }
            return None

        if feature == "IsHTTPS":
            if value == 0:
                return {
                    "title": "The website does not use HTTPS",
                    "explanation": (
                        "The connection uses HTTP instead of HTTPS, so the "
                        "connection does not provide HTTPS encryption."
                    ),
                }
            return None

        if feature == "TLDLegitimateProb":
            if value < 0.30:
                return {
                    "title": "The domain extension received a low trust-pattern score",
                    "explanation": (
                        "The domain extension is less commonly associated "
                        "with trusted website patterns."
                    ),
                }
            return None

        if feature == "URLCharProb":
            if value < 0.08:
                return {
                    "title": "The website address has a suspicious character pattern",
                    "explanation": (
                        "The combination of characters in this website address "
                        "contributed to the phishing result."
                    ),
                }
            return None

        if feature == "URLLength":
            if value >= 100:
                return {
                    "title": f"The URL is unusually long ({value} characters)",
                    "explanation": (
                        "Very long URLs can make suspicious parts of an address "
                        "harder for users to notice."
                    ),
                }
            return None

        if feature == "DomainLength":
            if value >= 50:
                return {
                    "title": f"The domain name is unusually long ({value} characters)",
                    "explanation": (
                        "Very long domain names can be used to create confusing "
                        "or misleading website addresses."
                    ),
                }
            return None

        if feature == "NoOfDegitsInURL":
            if value >= 3:
                return {
                    "title": f"The website address contains {value} digit(s)",
                    "explanation": (
                        "Numbers in a website address can sometimes be used "
                        "to imitate or alter familiar names."
                    ),
                }
            return None

        if feature == "DegitRatioInURL":
            if value >= 0.20:
                return {
                    "title": "A high proportion of the URL contains digits",
                    "explanation": (
                        "A large proportion of numbers can indicate an unusual "
                        "website-address structure."
                    ),
                }
            return None

        if feature == "NoOfOtherSpecialCharsInURL":
            if value >= 5:
                return {
                    "title": f"The URL contains {value} special characters",
                    "explanation": (
                        "A large number of special characters can make a URL "
                        "more difficult for users to inspect."
                    ),
                }
            return None

        if feature == "SpacialCharRatioInURL":
            if value >= 0.10:
                return {
                    "title": "The URL contains a high proportion of special characters",
                    "explanation": (
                        "A high proportion of special characters may indicate "
                        "a complicated or unusual URL structure."
                    ),
                }
            return None

        if feature == "NoOfObfuscatedChar":
            if value > 0:
                return {
                    "title": f"The URL contains {value} encoded character(s)",
                    "explanation": (
                        "Encoded characters can make parts of a URL more "
                        "difficult to recognise."
                    ),
                }
            return None

        if feature == "ObfuscationRatio":
            if value > 0:
                return {
                    "title": "Part of the URL uses encoded or hidden characters",
                    "explanation": (
                        "Encoding can be used to disguise parts of a website address."
                    ),
                }
            return None

        if feature == "NoOfEqualsInURL":
            if value >= 2:
                return {
                    "title": f"The URL contains {value} '=' characters",
                    "explanation": (
                        "Multiple URL parameters can create a more complicated "
                        "website address."
                    ),
                }
            return None

        if feature == "NoOfQMarkInURL":
            if value >= 1:
                return {
                    "title": "The URL contains query parameters",
                    "explanation": (
                        "Query parameters add extra information to the website "
                        "address and may make the destination harder to inspect."
                    ),
                }
            return None

        if feature == "NoOfAmpersandInURL":
            if value >= 2:
                return {
                    "title": f"The URL contains {value} '&' characters",
                    "explanation": (
                        "Multiple linked parameters can make a URL more complicated."
                    ),
                }
            return None

        # These two are too weak by themselves for normal-user phishing evidence.
        if feature in {
            "NoOfLettersInURL",
            "LetterRatioInURL",
            "TLDLength",
        }:
            return None

    return None

def _build_supported_xai_evidence(
    xai_evidence: Iterable[dict],
    prediction: str,
    limit: int = 5,
) -> list[dict]:

    supported = []

    for item in xai_evidence:

        feature = item.get("feature")
        value = item.get("value")
        shap_value = item.get("shap_value", 0)

        # Only keep SHAP evidence supporting the final prediction
        if prediction == "phishing" and shap_value <= 0:
            continue

        if prediction == "legitimate" and shap_value >= 0:
            continue

        explanation = _xai_explanation_for_feature(
            feature,
            value,
            prediction,
        )

        # Not meaningful enough for the current URL
        if explanation is None:
            continue

        supported.append({
            "title": explanation["title"],
            "explanation": explanation["explanation"],
            "source": "AI Feature Analysis",
            "feature": feature,
            "meaning": FEATURE_DESCRIPTIONS.get(
                feature,
                feature
            ),
            "value": value,
            "shap_value": shap_value,
            "lime_value": item.get("lime_value", 0),
        })

    supported = sorted(
        supported,
        key=lambda x: abs(x["shap_value"]),
        reverse=True
    )

    return supported[:limit]

def plain_text_explanation(
    prediction: str,
    risk: str,
    top_contributions: Iterable[dict],
    features: dict | None = None,
    url=None,
) -> str:
    """
    Generate a user-friendly explanation.

    For phishing:
    - Use only meaningful XAI evidence.
    - The points shown here must match the AI Explanation Evidence cards.

    For legitimate:
    - Keep the existing explanation logic for now.
    """

    top_contributions = list(top_contributions)

    # =========================================================
    # PHISHING RESULT
    # =========================================================

    if prediction == "phishing":

        phishing_info = detect_phishing_type(
            url,
            features
        )

        category = phishing_info["category"]

        intro = (
            f"This URL was classified as PHISHING with "
            f"{risk.lower()} risk. "
            f"The suspected attack type is {category}."
        )

        supported_xai = []

        technique_text = ""

        if phishing_info["techniques"]:

            technique_text = (
                " The detected phishing techniques include "
                +
                _english_join(
                    phishing_info["techniques"]
                )
                +
                "."
            )

        if features:

            evidence_with_values = []

            for item in top_contributions:

                feature = item.get("feature")

                evidence_with_values.append({
                    **item,
                    "value": features.get(feature),
                })

            supported_xai = _build_supported_xai_evidence(
                xai_evidence=evidence_with_values,
                prediction="phishing",
                limit=3,
            )

        if supported_xai:

            explanation_points = [
                card["title"]
                for card in supported_xai
            ]

            reasons = (
                " The most important URL characteristics supporting "
                "this result were "
                + _english_join(explanation_points)
                + "."
            )

        else:

            reasons = (
                " The AI identified a combination of URL characteristics "
                "that supported the phishing result, but no strong individual "
                "characteristic was suitable for a user-facing explanation."
            )

        return intro + technique_text + reasons

    # =========================================================
    # LEGITIMATE RESULT
    # Keep existing logic for now
    # =========================================================

    indicators = []

    if features:
        indicators = _feature_indicators(
            features,
            prediction,
        )

    indicators = indicators[:3]

    shap_drivers = [
        item
        for item in top_contributions
        if item.get("shap_value", 0) < 0
    ]

    shap_drivers = shap_drivers[:5]

    technical_features = []

    for item in shap_drivers:

        feature = item.get("feature")

        technical_features.append(
            FRIENDLY_NAMES.get(
                feature,
                feature
            )
        )

    technical_features = technical_features[:3]

    intro = (
        f"This URL was classified as LEGITIMATE with "
        f"{risk.lower()} risk."
    )

    if indicators:
        observable = (
            " Reassuring URL characteristics include "
            + _english_join(indicators)
        )
    else:
        observable = (
            " The URL did not show strong suspicious patterns "
            "in the explanation checks."
        )

    if technical_features:
        technical = (
            " The URL characteristics supporting this result included "
            + _english_join(technical_features)
            + "."
        )
    else:
        technical = ""

    return intro + observable + technical

def generate_xai_cards(
    xai_evidence: list[dict],
    prediction: str,
    limit: int = 5,
) -> list[dict]:
    """
    Generate only meaningful XAI evidence cards.

    Every card must represent an explanation that is relevant
    to the current URL and supports the final prediction.
    """

    return _build_supported_xai_evidence(
        xai_evidence=xai_evidence,
        prediction=prediction,
        limit=limit,
    )

def _english_join(items):
    items = list(items)

    if len(items) == 0:
        return ""

    if len(items) == 1:
        return items[0]

    if len(items) == 2:
        return f"{items[0]} and {items[1]}"

    return ", ".join(items[:-1]) + f", and {items[-1]}"