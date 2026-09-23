from typing import Iterable

import numpy as np

from .features import FEATURE_ORDER

_IS_HTTPS_IDX = FEATURE_ORDER.index("IsHTTPS")


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
    "NoOfSuspiciousWords": "Suspicious Words",
    "HasBrandOutsideDomain": "Brand Name Misuse",
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
    "NoOfSuspiciousWords": "suspicious words",
    "HasBrandOutsideDomain": "brand name misuse",
}


def risk_level(phishing_probability: float) -> str:
    """Map P(phish) to the Low / Medium / High tier used by the UI."""
    if phishing_probability < 0.50:
        return "Low"
    if phishing_probability < 0.80:
        return "Medium"
    return "High"


def is_https_only_verdict(vec: np.ndarray, model, threshold: float = 0.5) -> bool:
    """
    True when a "phishing" verdict is driven entirely by the missing-HTTPS
    signal: re-run the model on a counterfactual copy of `vec` with IsHTTPS
    flipped to 1 (same URL, imagined served over HTTPS) and check whether
    that alone flips the verdict to legitimate.

    IsHTTPS is the single most dominant feature (~36% importance) in this
    model, so a genuinely legitimate but plain-http:// site (informational
    pages, older institutional sites, some .gov pages) can get a confident
    "phishing" verdict on that basis alone. Rather than silently trusting or
    silently accusing, callers use this to downgrade the displayed verdict
    to a neutral "Unable to Verify" state instead of a hard phishing
    accusation -- while the raw model label/probability are still stored
    unchanged for accuracy reporting and audit purposes.
    """
    counterfactual = vec.copy()
    counterfactual[0, _IS_HTTPS_IDX] = 1
    return float(model.predict_proba(counterfactual)[0][1]) < threshold


def classify(vec: np.ndarray, features: dict, model, phish_threshold: float = 0.5,
             uncertain_threshold: float = 0.5) -> dict:
    """
    Single source of truth for turning the model's P(phishing) into the
    verdict shown to users (website scanner, XAI explain, extension).

    - p >= phish_threshold                  -> "phishing"
        ...unless the call is driven only by missing HTTPS (see
        is_https_only_verdict)             -> "uncertain" (reason "https_only")
    - uncertain_threshold <= p < phish_thr  -> "uncertain" (reason "borderline")
    - p < uncertain_threshold               -> "legitimate"

    The thresholds are tuned on a validation split during training (see
    notebooks/Model_Comparison_DT_RF.ipynb) instead of the default 0.5, so
    a hard "phishing" accusation needs a genuinely high score. `label`
    stays the model's raw 0.5 decision, so dashboard/aggregate statistics
    keep reporting true model behaviour.
    """
    proba = model.predict_proba(vec)[0]
    p = float(proba[1])
    result = {
        "label": int(p >= 0.5),
        "p_phish": p,
        "confidence": float(max(proba)),
        "prediction": "legitimate",
        "risk": "Low",
        "uncertain_reason": None,
    }
    if p >= phish_threshold:
        # Soften only if HTTPS alone would make the URL look clean (< uncertain
        # threshold), matching the original behaviour of this check.
        if features.get("IsHTTPS") == 0 and is_https_only_verdict(vec, model, uncertain_threshold):
            result.update(prediction="uncertain", risk="Medium", uncertain_reason="https_only")
        else:
            result.update(prediction="phishing", risk=risk_level(p) if p >= 0.5 else "Medium")
    elif p >= uncertain_threshold:
        result.update(prediction="uncertain", risk="Medium", uncertain_reason="borderline")
    return result


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


def _pct(value) -> str:
    """Render a 0-1 ratio as a percentage, e.g. 0.826 -> '82.6%'.

    Matches the frontend's one-decimal pct() formatting so the narrative text
    and the Detected Value shown in the Evidence card never disagree.
    """
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return str(value)


# Rough average feature values for each class in the training dataset
# (PhiUSIIL_Phishing_URL_Dataset.csv), used once (URLLength only) as a short
# reference point rather than repeated across every length-type card.
TRAINING_AVERAGES = {
    "URLLength": {"legitimate": 26, "phishing": 46},
}


def _feature_found(feature: str, prediction: str, value) -> str:
    """
    Short, factual "what the AI found" observation for an Evidence card.

    Deliberately just describes the observed value — no attacker-motive
    reasoning (that's _feature_why_matters()) and, except for URLLength, no
    repeated dataset-average comparisons.
    """
    if feature == "IsHTTPS":
        return (
            "This URL uses HTTPS." if int(value or 0) == 1
            else "This URL does not use HTTPS."
        )

    if feature == "URLCharProb":
        return (
            "The mix of characters in this address is unusual for a "
            "trustworthy website." if prediction == "phishing"
            else "The mix of characters in this address looks typical of a "
            "trustworthy website."
        )

    if feature == "NoOfSubDomain":
        try:
            count = int(float(value))
        except (TypeError, ValueError):
            return "The model evaluated the number of subdomains in this URL."
        if count == 0:
            return "This URL has no extra subdomains."
        if count == 1:
            return "This URL has one extra subdomain."
        return f"This URL has {count} extra subdomains."

    if feature == "IsDomainIP":
        return (
            "This address uses a raw IP address instead of a domain name."
            if int(value or 0) == 1
            else "This address uses a normal domain name, not an IP address."
        )

    if feature == "HasObfuscation":
        return (
            "This URL contains an obfuscation pattern (encoded characters) "
            "that can hide parts of the address." if int(value or 0) == 1
            else "No obfuscation pattern was found in this URL."
        )

    if feature == "URLLength":
        avg = TRAINING_AVERAGES["URLLength"]
        return (
            f"This URL is {_number(value)} characters long (training data "
            f"average: ~{avg['legitimate']} for legitimate URLs, ~{avg['phishing']} "
            "for phishing)."
        )

    if feature == "DomainLength":
        return f"The domain name itself is {_number(value)} characters long."

    if feature == "NoOfLettersInURL":
        return f"This URL contains {_number(value)} letters."

    if feature == "LetterRatioInURL":
        return f"About {_pct(value)} of this URL's characters are letters."

    if feature == "NoOfDegitsInURL":
        count = _number(value)
        return (
            "This URL contains no digits." if count in ("0", "0.0")
            else f"This URL contains {count} digit(s)."
        )

    if feature == "DegitRatioInURL":
        return f"Digits make up about {_pct(value)} of this URL's characters."

    if feature == "TLDLegitimateProb":
        return (
            f"This URL's domain suffix has a legitimacy score of {_number(value)} "
            "(0 = rarely seen on legitimate sites, 1 = commonly seen)."
        )

    if feature == "TLDLength":
        return f"The domain suffix is {_number(value)} character(s) long."

    if feature in ("NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL"):
        friendly = {
            "NoOfEqualsInURL": "'=' characters",
            "NoOfQMarkInURL": "'?' characters",
            "NoOfAmpersandInURL": "'&' characters",
        }[feature]
        return f"This URL has {_number(value)} {friendly}."

    if feature == "NoOfOtherSpecialCharsInURL":
        return f"This URL contains {_number(value)} other special character(s)."

    if feature == "SpacialCharRatioInURL":
        return f"About {_pct(value)} of this URL's characters are special symbols."

    if feature == "NoOfObfuscatedChar":
        return f"{_number(value)} character(s) in this URL use encoding tricks."

    if feature == "ObfuscationRatio":
        return f"About {_pct(value)} of this URL uses encoding tricks."

    if feature == "NoOfSuspiciousWords":
        n = int(float(value or 0))
        return (
            "No login, account or payment wording was found in this URL." if n == 0
            else f"This URL contains {n} login/account/payment-related word(s) "
            "(such as 'login', 'verify', 'account', 'bank')."
        )

    if feature == "HasBrandOutsideDomain":
        return (
            "A well-known brand name appears in this URL, but the website is "
            "not that brand's official domain." if int(value or 0) == 1
            else "No well-known brand name is used outside its official website."
        )

    # Generic fallback for any remaining feature without a dedicated observation.
    return f"The detected value for this characteristic is {_number(value)}."


def _feature_why_matters(feature: str, prediction: str) -> str:
    """
    Short, prediction-aware "why this feature matters" security explanation
    for an Evidence card — independent of the exact observed number.
    """
    p = prediction == "phishing"

    if feature == "IsHTTPS":
        return (
            "Legitimate services almost always use HTTPS; a missing secure "
            "connection is a red flag attackers often skip to save effort."
            if p else
            "A secure HTTPS connection is standard for real, modern websites."
        )

    if feature == "URLCharProb":
        return (
            "Phishing URLs often mix characters in ways rarely seen in real "
            "domain names." if p else
            "This character pattern matches what's normally seen in real, "
            "trustworthy domain names."
        )

    if feature == "NoOfSubDomain":
        return (
            "Extra subdomains can be used to disguise the real registered "
            'domain (for example, "login.paypal.attacker.com" can look like '
            "it belongs to PayPal when the real domain is attacker.com)."
            if p else
            "A normal subdomain structure (such as www.site.com) is typical "
            "of legitimate websites."
        )

    if feature == "IsDomainIP":
        return (
            "Legitimate services rarely expose a raw IP address to users; "
            "attackers use this to avoid registering a traceable domain."
            if p else
            "Using a proper domain name rather than a raw IP is standard "
            "for real websites."
        )

    if feature == "HasObfuscation":
        return (
            "Obfuscation (such as encoded characters) can hide the real "
            "destination of a link from a user glancing at the address."
            if p else
            "A clean, unobfuscated address is typical of legitimate links."
        )

    if feature == "URLLength":
        return (
            "Attackers sometimes lengthen URLs with extra subdomains, words, "
            "or parameters to hide the real destination or imitate a trusted "
            "brand — though many legitimate sites also use long URLs, so "
            "length alone is never treated as proof either way; it's only "
            "one of several signals the model weighs together."
            if p else
            "Most legitimate sites use short, simple URLs, so a typical "
            "length is consistent with a real, established website — though "
            "length alone is only one of several signals the model weighs "
            "together."
        )

    if feature in ("DomainLength", "NoOfLettersInURL"):
        return (
            "Attackers often pad the domain or path with extra words to "
            "look convincing or brand-like." if p else
            "A short, simple domain and wording is typical of an "
            "established website."
        )

    if feature in ("LetterRatioInURL", "DegitRatioInURL"):
        return (
            "An unusual mix of letters, digits, and symbols can indicate an "
            "artificially generated or disguised address." if p else
            "A normal balance of letters and digits is typical of a "
            "human-chosen domain name."
        )

    if feature == "NoOfDegitsInURL":
        return (
            "Phishing domains occasionally use extra digits for randomly "
            "generated or auto-created addresses." if p else
            "Legitimate URLs usually contain very few digits."
        )

    if feature == "TLDLegitimateProb":
        return (
            "Some domain suffixes are cheaper or easier to register "
            "anonymously and are disproportionately used for phishing." if p
            else "This suffix is one commonly used by real, established "
            "websites."
        )

    if feature == "TLDLength":
        return (
            "Unusual suffix lengths are less common among mainstream "
            "domains." if p else
            "A standard suffix length is typical of mainstream domains."
        )

    if feature in (
        "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
        "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
    ):
        return (
            "Cluttered addresses with many special characters or query "
            "parameters can be used to hide redirects or tracking." if p else
            "Few unusual characters is typical of a clean, human-readable "
            "address."
        )

    if feature in ("NoOfObfuscatedChar", "ObfuscationRatio"):
        return (
            "Encoding tricks (like '%' escape codes) can disguise the real "
            "address a link points to." if p else
            "Little to no encoding is typical of a transparent, legitimate "
            "link."
        )

    if feature == "NoOfSuspiciousWords":
        return (
            "Phishing links often add words like 'login', 'verify' or "
            "'account' to make a fake page look official and urgent." if p else
            "Addresses without urgent account or payment wording are typical "
            "of ordinary web pages."
        )

    if feature == "HasBrandOutsideDomain":
        return (
            "Attackers put a trusted brand's name in the path or subdomain "
            "(e.g. site.com/paypal/login) to impersonate it." if p else
            "The address does not borrow another company's brand name."
        )

    # Generic fallback for any remaining feature without a dedicated reason.
    return (
        "This pattern is one of several the model weighs together, learned "
        "from real phishing and legitimate URLs."
    )


# Short, lowercase clauses used to build the single "combined signals" sentence
# in build_reason_bullets(). These are intentionally brief (not full sentences)
# since the full, grounded explanation for each feature already lives in the
# Evidence cards via _feature_description().
FEATURE_CLAUSES = {
    "IsHTTPS": ("a missing HTTPS connection", "a secure HTTPS connection"),
    "URLLength": ("an unusually long URL", "a typical URL length"),
    "DomainLength": ("a longer-than-usual domain name", "a typical domain length"),
    "NoOfLettersInURL": ("an unusually high letter count", "a typical letter count"),
    "LetterRatioInURL": ("an unusual letter-to-symbol ratio", "a normal letter-to-symbol ratio"),
    "NoOfDegitsInURL": ("extra digits in the address", "very few digits in the address"),
    "DegitRatioInURL": ("a higher-than-usual share of digits", "a normal, low share of digits"),
    "TLDLegitimateProb": ("a domain suffix rarely seen on legitimate sites", "a domain suffix commonly seen on legitimate sites"),
    "TLDLength": ("an unusual domain-suffix length", "a standard domain-suffix length"),
    "NoOfSubDomain": ("multiple subdomains", "a normal subdomain structure"),
    "IsDomainIP": ("an IP address used instead of a domain name", "a normal domain name"),
    "HasObfuscation": ("obfuscation patterns in the address", "no obfuscation patterns"),
    "URLCharProb": ("a character pattern typical of phishing URLs", "a character pattern typical of legitimate URLs"),
    "NoOfEqualsInURL": ("unusual query-parameter characters", "few or no query-parameter characters"),
    "NoOfQMarkInURL": ("unusual query-string characters", "few or no query-string characters"),
    "NoOfAmpersandInURL": ("chained query parameters", "few or no chained query parameters"),
    "NoOfOtherSpecialCharsInURL": ("unusual special characters in the address", "few unusual characters in the address"),
    "SpacialCharRatioInURL": ("a high share of special symbols", "a normal, low share of special symbols"),
    "NoOfObfuscatedChar": ("encoded/obfuscated characters", "no encoded characters"),
    "ObfuscationRatio": ("a high proportion of obfuscated characters", "little to no obfuscation"),
    "NoOfSuspiciousWords": ("account/login/payment wording in the address", "no account or payment wording"),
    "HasBrandOutsideDomain": ("a brand name used outside its official website", "no misused brand names"),
}


def _feature_clause(feature: str, prediction: str) -> str:
    """Short clause describing a feature's direction for the combined-signal sentence."""
    phishing_clause, legitimate_clause = FEATURE_CLAUSES.get(
        feature,
        (
            f"an unusual value for {FRIENDLY_NAMES.get(feature, feature)}",
            f"a typical value for {FRIENDLY_NAMES.get(feature, feature)}",
        ),
    )
    return phishing_clause if prediction == "phishing" else legitimate_clause


def _combined_signal_sentence(
    prediction: str,
    top_contributions: Iterable[dict],
    limit: int = 3,
) -> str:
    """
    One readable sentence synthesizing several supporting ML signals, instead of
    a raw-value bullet per feature. Numbers/thresholds still live in the
    Evidence cards below — this sentence only names the pattern.
    """
    want_positive = prediction == "phishing"
    clauses: list[str] = []
    seen: set[str] = set()

    for item in top_contributions:
        feature = item.get("feature")
        try:
            shap_value = float(item.get("shap_value", 0.0))
        except (TypeError, ValueError):
            continue

        supports_prediction = shap_value > 0 if want_positive else shap_value < 0
        if not supports_prediction:
            continue

        clause = _feature_clause(feature, prediction)
        if clause in seen:
            continue
        seen.add(clause)
        clauses.append(clause)
        if len(clauses) >= limit:
            break

    if not clauses:
        return ""

    # NOTE: avoid the literal " — " sequence here. The frontend's why_detected
    # renderer splits each string on the first " — " to bold a "Title" prefix
    # (used by the old "Title — description" bullet format); this sentence has
    # no title, so that pattern must not appear inside it.
    joined = _english_join(clauses)
    if prediction == "phishing":
        return (
            f"The model's decision was also reinforced by structural signals such "
            f"as {joined}, patterns it learned from confirmed phishing examples "
            "during training."
        )
    return (
        f"The model also found supporting structural signals such as {joined}, "
        "patterns commonly seen on legitimate websites during training."
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
    Each card carries a short factual "found" observation (_feature_found())
    and a short "why_it_matters" security explanation (_feature_why_matters()),
    kept separate so the UI can render them as two distinct lines above the
    technical Feature/Detected Value/SHAP/LIME block.
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
            "found": _feature_found(feature, prediction, value),
            "why_it_matters": _feature_why_matters(feature, prediction),
            "support": (
                "Supports phishing classification"
                if prediction == "phishing"
                else "Supports legitimate classification"
            ),
        })

    candidates.sort(key=lambda x: abs(x["shap_contribution"]), reverse=True)
    return candidates[:limit]


# Short, higher-level paraphrase per attack technique for "Why was this
# detected?" — deliberately DIFFERENT wording from the full indicator
# sentences shown in the Phishing Attack Analysis section (attack_analysis
# ["indicators"]), so the two sections don't repeat the same sentence. Attack
# Analysis answers "what attack behaviour is this"; this dict answers "why
# did that push the AI toward phishing" at a summary level.
TECHNIQUE_SUMMARY_CLAUSES = {
    "Brand Impersonation": (
        "The domain contains wording associated with a trusted brand that "
        "doesn't match that brand's official domain."
    ),
    "Typosquatting": (
        "Part of the address closely resembles a trusted brand name, a "
        "common typosquatting pattern."
    ),
    "Credential Harvesting": (
        "The URL contains account- or verification-related wording often "
        "used to lure users into entering credentials."
    ),
    "Fake Security Alert": (
        "The URL uses alarming or urgent wording designed to pressure a "
        "quick reaction."
    ),
    "Malware Delivery": (
        "The URL references downloading or installing software, a common "
        "malware-delivery pattern."
    ),
    "URL Obfuscation": (
        "Parts of the address are obscured in a way that can hide its real "
        "destination."
    ),
    "IP Address Hosting": (
        "The site is hosted on a raw IP address rather than a registered "
        "domain name."
    ),
    "Subdomain Manipulation": (
        "The domain structure contains subdomain patterns that are less "
        "common among established websites."
    ),
    "Suspicious Top-Level Domain": (
        "The domain suffix pattern shows similarities with domains "
        "frequently used in phishing campaigns."
    ),
    "Randomized / Numeric Domain": (
        "The domain contains numeric patterns typical of automatically "
        "generated addresses."
    ),
    "Suspicious URL Pattern": (
        "Additional URL characteristics reinforced the phishing prediction."
    ),
}


def _technique_summary_bullets(attack_analysis: dict | None, limit: int) -> list[str]:
    """Paraphrased, non-duplicate summary of each detected attack technique."""
    if not attack_analysis:
        return []
    techniques = attack_analysis.get("techniques") or []
    bullets = [
        TECHNIQUE_SUMMARY_CLAUSES[t] for t in dict.fromkeys(techniques)
        if t in TECHNIQUE_SUMMARY_CLAUSES
    ]
    return bullets[:limit]


def build_reason_bullets(
    prediction: str,
    features: dict,
    top_contributions: Iterable[dict],
    attack_analysis: dict | None = None,
    limit: int = 4,
) -> list[str]:
    """
    Explain WHY a verdict was reached in plain language, leading with a
    summary of the detected attack techniques and closing with the
    supporting structural ML signals — rather than raw feature values.

    For phishing, each bullet paraphrases a technique already identified by
    detect_phishing_type() using TECHNIQUE_SUMMARY_CLAUSES (deliberately
    reworded, not the same sentence shown in the Phishing Attack Analysis
    section) and closes with one sentence synthesizing the supporting
    structural ML signals. For legitimate, it's a single narrative sentence
    built the same way. Exact feature values and SHAP/LIME numbers are left
    to the separate AI Explanation Evidence cards (see build_evidence()).
    """
    if prediction == "phishing":
        bullets = _technique_summary_bullets(attack_analysis, limit=max(limit - 1, 1))

        if len(bullets) < limit:
            summary = _combined_signal_sentence(prediction, top_contributions, limit=3)
            if summary:
                bullets.append(summary)

        if not bullets:
            bullets.append(
                "This URL was flagged as phishing because its overall structure "
                "closely matches patterns the model learned from confirmed "
                "phishing URLs, even though no single, obvious red flag stands out."
            )

        return bullets[:limit]

    # Legitimate: one narrative sentence rather than a per-feature bullet list.
    summary = _combined_signal_sentence(prediction, top_contributions, limit=4)
    if summary:
        return [summary]

    return [
        "This URL was classified as legitimate because its overall structure did "
        "not match the patterns the model associates with phishing URLs."
    ]


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
