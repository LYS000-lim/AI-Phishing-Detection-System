import ipaddress
import os
import re
from urllib.parse import urlparse

import joblib
import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_OUTPUTS = os.path.join(_HERE, "..", "..", "outputs")

URL_ONLY_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",

    # new
    "BrandDomainMismatch",
    "SuspiciousKeywordCount",
    "DocumentationIndicator",
]

FEATURE_ORDER = URL_ONLY_FEATURES  # exported name for other modules

_OBFUSCATED = re.compile(r"%[0-9a-fA-F]{2}|@|0x[0-9a-fA-F]+")

_TLD_LOOKUP = None
_CHAR_LOOKUP = None


def _load_lookups():
    global _TLD_LOOKUP, _CHAR_LOOKUP
    if _TLD_LOOKUP is None:
        _TLD_LOOKUP = joblib.load(
            os.path.join(_OUTPUTS, "tld_probability_lookup.joblib"),
        )
    if _CHAR_LOOKUP is None:
        _CHAR_LOOKUP = joblib.load(
            os.path.join(_OUTPUTS, "char_probability_lookup.joblib"),
        )


def _is_ip(host: str) -> int:
    try:
        ipaddress.ip_address(host.split(":")[0])
        return 1
    except ValueError:
        return 0


# ==============================
# Step 3 Feature Engineering
# ==============================

BRAND_KEYWORDS = {
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "github",
    "facebook",
    "instagram",
    "amazon",
    "netflix"
}


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "account",
    "security",
    "secure",
    "password",
    "confirm",
    "update",
    "signin",
    "wallet"
}


LEGITIMATE_PATH_KEYWORDS = {
    "docs",
    "documentation",
    "api",
    "reference",
    "tutorial",
    "guide",
    "learn",
    "wiki",
    "manual",
    "developer"
}


def extract_domain(url):
    """
    Extract registered domain.
    Example:
    https://github.com/login

    return:
    github.com
    """

    try:
        parsed = urlparse(url)

        host = parsed.netloc.lower()

        if host.startswith("www."):
            host = host[4:]

        return host

    except:
        return ""


def count_keyword_occurrence(url, keyword_set):

    url_lower = url.lower()

    count = 0

    for word in keyword_set:

        if word in url_lower:
            count += 1

    return count



def brand_domain_mismatch(url):

    """
    Detect:
    
    github-login-security.example.com

    Brand exists,
    but actual domain is not github.com
    """

    domain = extract_domain(url)

    url_lower = url.lower()


    for brand in BRAND_KEYWORDS:

        if brand in url_lower:

            if not domain.endswith(brand + ".com"):

                return 1


    return 0



def documentation_indicator(url):

    """
    Reduce false positive from:
    
    developer.mozilla.org/docs
    numpy.org/doc
    scikit-learn.org/documentation
    """

    url_lower = url.lower()

    for word in LEGITIMATE_PATH_KEYWORDS:

        if word in url_lower:

            return 1


    return 0

def compute_features(url: str, tld_lookup: dict, char_lookup: dict) -> dict:
    """
    Pure function: compute the URL features used by the ML model for a raw URL string
    using explicit lookup tables. Called by BOTH the training script
    and the inference path so the model sees identical feature values
    in both phases.
    """
    raw = url.strip()
    if not raw.lower().startswith(("http://", "https://")):
        raw = "http://" + raw

    parsed = urlparse(raw)
    domain = parsed.netloc.lower()
    host = domain.split(":")[0]

    url_len = len(raw)
    letters = re.findall(r"[a-zA-Z]", raw)
    digits = re.findall(r"[0-9]", raw)
    specials = re.findall(r"[^a-zA-Z0-9]", raw)
    other_specials = [
        c for c in specials if c not in ("=", "?", "&", "/", ":", ".")
    ]

    parts = host.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    n_sub = max(len(parts) - 2, 0)

    obfuscated = _OBFUSCATED.findall(raw)
    n_obf = len(obfuscated)

    char_probs = [char_lookup.get(c, 1e-6) for c in raw.lower()]

    return {
        "URLLength": url_len,
        "DomainLength": len(domain),
        "IsDomainIP": _is_ip(host),

        "TLDLegitimateProb": float(tld_lookup.get(tld, 0.5)),
        "URLCharProb": float(np.mean(char_probs)) if char_probs else 0.0,

        "TLDLength": len(tld),
        "NoOfSubDomain": n_sub,

        "HasObfuscation": int(n_obf > 0),
        "NoOfObfuscatedChar": n_obf,
        "ObfuscationRatio": n_obf / max(url_len, 1),

        "NoOfLettersInURL": len(letters),
        "LetterRatioInURL": round(len(letters) / max(url_len, 1), 3),

        "NoOfDegitsInURL": len(digits),
        "DegitRatioInURL": round(len(digits) / max(url_len, 1), 3),

        "NoOfEqualsInURL": raw.count("="),
        "NoOfQMarkInURL": raw.count("?"),
        "NoOfAmpersandInURL": raw.count("&"),

        "NoOfOtherSpecialCharsInURL": len(other_specials),
        "SpacialCharRatioInURL": round(
            len(other_specials) / max(url_len,1),
            3
        ),

        "IsHTTPS": int(parsed.scheme == "https"),


        # ==========================
        # New Step 3 ML Features
        # ==========================

        "BrandDomainMismatch":
            brand_domain_mismatch(raw),

        "SuspiciousKeywordCount":
            count_keyword_occurrence(
                raw,
                SUSPICIOUS_KEYWORDS
            ),

        "DocumentationIndicator":
            documentation_indicator(raw),
    }


def extract_features(url: str) -> dict:
    """Inference-side wrapper: uses module-level lookups loaded from disk."""
    _load_lookups()
    return compute_features(url, _TLD_LOOKUP, _CHAR_LOOKUP)


def feature_vector(url: str) -> np.ndarray:
    """Features as a (1, n) array in the exact order the model expects."""
    feats = extract_features(url)
    return np.array([[feats[name] for name in FEATURE_ORDER]])
