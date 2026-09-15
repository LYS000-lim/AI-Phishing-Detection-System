from typing import Iterable


# Base labels used in the redesigned result interface.
# A few labels (for example URLCharProb) are made prediction-aware by
# _feature_title() so the wording never contradicts the verdict.
FEATURE_TITLES = {
    "URLLength": "URL Length",
    "DomainLength": "Domain Length",
    "IsDomainIP": "Domain Address Type",
    "TLDLegitimateProb": "Top-Level Domain Pattern",
    "URLCharProb": "URL Character Pattern",
    "TLDLength": "Top-Level Domain Length",
    "NoOfSubDomain": "Subdomain Count Pattern",
    "HasObfuscation": "URL Obfuscation",
    "NoOfObfuscatedChar": "Obfuscated Characters",
    "ObfuscationRatio": "Obfuscation Ratio",
    "NoOfLettersInURL": "Letter Count",
    "LetterRatioInURL": "Letter Ratio",
    "NoOfDegitsInURL": "Digit Count",
    "DegitRatioInURL": "Digit Ratio",
    "NoOfEqualsInURL": "Query Assignment Characters",
    "NoOfQMarkInURL": "Query Separators",
    "NoOfAmpersandInURL": "Query Parameter Separators",
    "NoOfOtherSpecialCharsInURL": "Special Characters",
    "SpacialCharRatioInURL": "Special Character Ratio",
    "IsHTTPS": "HTTPS Usage",
}


# Friendly wording for the backward-compatible one-sentence summary.
FRIENDLY_NAMES = {
    "URLLength": "URL length",
    "DomainLength": "domain length",
    "IsDomainIP": "domain address type",
    "TLDLegitimateProb": "top-level-domain pattern",
    "URLCharProb": "URL character pattern",
    "TLDLength": "top-level-domain length",
    "NoOfSubDomain": "subdomain count pattern",
    "HasObfuscation": "URL obfuscation",
    "NoOfObfuscatedChar": "obfuscated characters",
    "ObfuscationRatio": "obfuscation ratio",
    "NoOfLettersInURL": "letter count",
    "LetterRatioInURL": "letter ratio",
    "NoOfDegitsInURL": "digit count",
    "DegitRatioInURL": "digit ratio",
    "NoOfEqualsInURL": "query assignments",
    "NoOfQMarkInURL": "query separators",
    "NoOfAmpersandInURL": "chained query parameters",
    "NoOfOtherSpecialCharsInURL": "special characters",
    "SpacialCharRatioInURL": "special-character ratio",
    "IsHTTPS": "HTTPS usage",
}


def risk_level(phishing_probability: float) -> str:
    """Map P(phish) to the Low / Medium / High tier used by the UI."""
    if phishing_probability < 0.50:
        return "Low"
    if phishing_probability < 0.80:
        return "Medium"
    return "High"


def _feature_title(feature: str, prediction: str) -> str:
    """Return a verdict-aware title that does not contradict the result."""
    if feature == "URLCharProb":
        return (
            "Suspicious URL Character Pattern"
            if prediction == "phishing"
            else "Legitimate URL Character Pattern"
        )
    return FEATURE_TITLES.get(feature, feature)


def _number(value, digits: int = 5) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return str(value)
    if n.is_integer():
        return str(int(n))
    return f"{n:.{digits}f}".rstrip("0").rstrip(".")


def _feature_description(feature: str, prediction: str, value) -> str:
    """
    Describe the OBSERVED feature value separately from the model direction.

    This is intentionally conservative. A SHAP contribution tells us that a
    value pushed the model toward a class; it does not prove that the value is
    inherently malicious or safe in every URL.
    """
    supports = "phishing" if prediction == "phishing" else "legitimate"

    if feature == "IsHTTPS":
        if int(value or 0) == 1:
            if prediction == "legitimate":
                return (
                    "The URL uses HTTPS, which is a normal characteristic of "
                    "legitimate modern websites."
                )
            return (
                "The URL uses HTTPS. In this prediction, the HTTPS feature value "
                "still contributed toward the phishing classification based on "
                "patterns learned by the model."
            )
        if prediction == "phishing":
            return (
                "The URL does not use HTTPS, so the address lacks the HTTPS "
                "indicator commonly expected on modern legitimate services."
            )
        return (
            "The URL does not use HTTPS. Even so, this feature value supported "
            "the legitimate classification in this model prediction."
        )

    if feature == "URLCharProb":
        if prediction == "phishing":
            return (
                "The combination of characters in the website address contributed "
                "to the phishing result."
            )
        return (
            "The website address has a character pattern more consistent with "
            "legitimate URLs."
        )

    if feature == "NoOfSubDomain":
        try:
            count = int(float(value))
        except (TypeError, ValueError):
            count = None

        if count == 0:
            observed = "No additional subdomains were detected."
        elif count == 1:
            observed = "One additional subdomain was detected."
        elif count is not None:
            observed = f"{count} additional subdomains were detected."
        else:
            observed = "The model evaluated the number of subdomains in the URL."

        return (
            f"{observed} This subdomain-count value supported the {supports} "
            "classification based on patterns learned from the training data."
        )

    if feature == "IsDomainIP":
        uses_ip = int(value or 0) == 1
        if uses_ip:
            observed = "The address uses an IP address instead of a normal domain name."
        else:
            observed = "The URL uses a normal domain name rather than an IP address."
        return (
            f"{observed} This domain-address value supported the {supports} "
            "classification in this prediction."
        )

    if feature == "HasObfuscation":
        has_obfuscation = int(value or 0) == 1
        if has_obfuscation:
            observed = (
                "The URL contains an obfuscation pattern that can make parts of "
                "the address harder to recognise."
            )
        else:
            observed = "No URL-obfuscation pattern was detected."
        return (
            f"{observed} This feature value supported the {supports} classification."
        )

    if feature == "URLLength":
        return (
            f"The detected URL length is {_number(value)} characters. This value "
            f"supported the {supports} classification based on patterns learned "
            "by the model."
        )

    if feature == "DomainLength":
        return (
            f"The detected domain length is {_number(value)} characters. This value "
            f"supported the {supports} classification based on learned URL patterns."
        )

    if feature == "TLDLegitimateProb":
        return (
            f"The top-level-domain pattern value is {_number(value)}. This value "
            f"supported the {supports} classification based on the training data."
        )

    if feature == "TLDLength":
        return (
            f"The top-level-domain length is {_number(value)}. This value supported "
            f"the {supports} classification in this prediction."
        )

    # Generic but academically safe fallback for all remaining numeric features.
    return (
        f"The detected value for this URL characteristic is {_number(value)}. "
        f"This value supported the {supports} classification based on patterns "
        "learned by the model."
    )


def _lime_weight_for_feature(feature: str, lime_rules: Iterable[dict]) -> float:
    """Find the LIME rule that references a feature and return its weight."""
    for item in lime_rules:
        rule = str(item.get("rule", ""))
        if feature in rule:
            try:
                return float(item.get("weight", 0.0))
            except (TypeError, ValueError):
                return 0.0
    return 0.0


def build_evidence(
    prediction: str,
    features: dict,
    shap_features: Iterable[dict],
    lime_rules: Iterable[dict],
    limit: int = 3,
) -> list[dict]:
    """
    Combine SHAP + LIME into a small list of evidence cards.

    For phishing, only SHAP values pushing toward class 1 are shown.
    For legitimate, only SHAP values pushing away from class 1 are shown.
    The title and description are generated from the same helper functions used
    by build_reason_bullets(), keeping both UI sections one-to-one aligned.
    """
    want_positive = prediction == "phishing"
    candidates = []

    for item in shap_features:
        feature = item.get("feature")
        try:
            shap_value = float(item.get("shap_value", 0.0))
        except (TypeError, ValueError):
            continue

        supports_prediction = shap_value > 0 if want_positive else shap_value < 0
        if not supports_prediction:
            continue

        value = features.get(feature)
        lime_weight = _lime_weight_for_feature(feature, lime_rules)
        candidates.append({
            "title": _feature_title(feature, prediction),
            "feature": feature,
            "detected_value": value,
            "shap_contribution": round(shap_value, 5),
            "lime_contribution": round(lime_weight, 5),
            "description": _feature_description(feature, prediction, value),
            "support": (
                "Supports phishing classification"
                if prediction == "phishing"
                else "Supports legitimate classification"
            ),
        })

    candidates.sort(key=lambda x: abs(x["shap_contribution"]), reverse=True)
    return candidates[:limit]


def build_reason_bullets(
    prediction: str,
    features: dict,
    top_contributions: Iterable[dict],
    attack_analysis: dict | None = None,
    limit: int = 3,
) -> list[str]:
    """
    Build reason bullets from the SAME SHAP-supported features as evidence.

    Attack-analysis indicators remain in the separate Phishing Attack Analysis
    section. This keeps the Why section directly paired with the three XAI cards.
    """
    want_positive = prediction == "phishing"
    bullets: list[str] = []

    for item in top_contributions:
        feature = item.get("feature")
        try:
            shap_value = float(item.get("shap_value", 0.0))
        except (TypeError, ValueError):
            continue

        supports_prediction = shap_value > 0 if want_positive else shap_value < 0
        if not supports_prediction:
            continue

        value = features.get(feature)
        title = _feature_title(feature, prediction)
        description = _feature_description(feature, prediction, value)
        bullets.append(f"{title} — {description}")

        if len(bullets) >= limit:
            break

    if not bullets:
        fallback_title = (
            "Phishing URL Pattern"
            if prediction == "phishing"
            else "Legitimate URL Pattern"
        )
        fallback_text = (
            "The website structure matches URL patterns the model learned from phishing examples."
            if prediction == "phishing"
            else "The URL structure matches patterns the model learned from legitimate examples."
        )
        bullets.append(f"{fallback_title} — {fallback_text}")

    return bullets[:limit]


def plain_text_explanation(
    prediction: str,
    risk: str,
    top_contributions: Iterable[dict],
) -> str:
    """Backward-compatible one-sentence explanation used by older views."""
    push_phish, push_legit = [], []
    for item in top_contributions:
        name = FRIENDLY_NAMES.get(item["feature"], item["feature"])
        (push_phish if item["shap_value"] >= 0 else push_legit).append(name)

    if prediction == "phishing":
        drivers = push_phish[:3] or ["several suspicious URL patterns"]
        joined = _english_join(drivers)
        return (
            f"This URL was classified as PHISHING with {risk.lower()} risk. "
            f"The strongest model evidence included {joined}."
        )

    drivers = push_legit[:3] or ["standard, well-formed URL patterns"]
    joined = _english_join(drivers)
    return (
        f"This URL was classified as LEGITIMATE with {risk.lower()} risk. "
        f"The strongest model evidence included {joined}."
    )


def _english_join(items):
    items = list(items)
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"
