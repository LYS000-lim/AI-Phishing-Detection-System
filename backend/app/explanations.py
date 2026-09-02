"""
Human-facing explanation helpers.

- risk_level(): maps phishing probability to Low / Medium / High
- plain_text_explanation(): turns the top SHAP contributions into a
  short paragraph the user can actually read on the result card
"""

from typing import Iterable

# Friendly, non-technical names for the URL features shown on the UI.
FRIENDLY_NAMES = {
    "URLLength": "a very long URL",
    "DomainLength": "an unusually long domain name",
    "IsDomainIP": "an IP address used in place of a domain name",
    "TLDLegitimateProb": "a top-level domain often used for phishing",
    "URLCharProb": "an unusual mix of characters in the URL",
    "TLDLength": "an unusual top-level domain length",
    "NoOfSubDomain": "a large number of subdomains",
    "HasObfuscation": "URL-encoding tricks used to hide characters",
    "NoOfObfuscatedChar": "several obfuscated characters",
    "ObfuscationRatio": "a high proportion of obfuscated characters",
    "NoOfLettersInURL": "many letters packed into the URL",
    "LetterRatioInURL": "a suspicious letter-to-length ratio",
    "NoOfDegitsInURL": "a lot of digits in the URL",
    "DegitRatioInURL": "a high digit-to-length ratio",
    "NoOfEqualsInURL": "many '=' query parameters",
    "NoOfQMarkInURL": "several '?' query separators",
    "NoOfAmpersandInURL": "several '&' chained parameters",
    "NoOfOtherSpecialCharsInURL": "many unusual special characters",
    "SpacialCharRatioInURL": "a high special-character ratio",
    "IsHTTPS": "the use of HTTPS (encrypted connection)",
}


def risk_level(phishing_probability: float) -> str:
    """
    Map P(phish) to a Low/Medium/High tier for the result card.

    Thresholds are tuned conservatively so the "High risk" pill is only
    shown for confident phishing predictions - a borderline 0.55 verdict
    stays Medium, not High. This avoids alarming users when the model
    is genuinely uncertain.
    """
    if phishing_probability < 0.50:
        return "Low"
    if phishing_probability < 0.80:
        return "Medium"
    return "High"


def plain_text_explanation(
    prediction: str,
    risk: str,
    top_contributions: Iterable[dict],
) -> str:
    """
    Turn the top SHAP contributions into one readable sentence.

    Convention: shap_value > 0 pushes toward Phishing(1), < 0 toward
    Legitimate(0), because the deployment model treats class 1 as phish.
    """
    push_phish, push_legit = [], []
    for item in top_contributions:
        name = FRIENDLY_NAMES.get(item["feature"], item["feature"])
        (push_phish if item["shap_value"] >= 0 else push_legit).append(name)

    if prediction == "phishing":
        drivers = push_phish[:3] or ["several suspicious URL patterns"]
        joined = _english_join(drivers)
        return (
            f"This URL was flagged as PHISHING with {risk.lower()} risk "
            f"because it shows {joined}."
        )

    drivers = push_legit[:3] or ["standard, well-formed URL patterns"]
    joined = _english_join(drivers)
    return (
        f"This URL looks LEGITIMATE with {risk.lower()} risk because it shows "
        f"{joined}."
    )


def _english_join(items):
    items = list(items)
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"
