import ipaddress
import os
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import joblib
import numpy as np

from .phishing_type import BRANDS, CREDENTIAL_KEYWORDS, FINANCIAL_KEYWORDS, _is_official_host

_HERE = os.path.dirname(os.path.abspath(__file__))
_OUTPUTS = os.path.join(_HERE, "..", "..", "outputs")

URL_ONLY_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP", "TLDLegitimateProb",
    "URLCharProb", "TLDLength", "NoOfSubDomain", "HasObfuscation",
    "NoOfObfuscatedChar", "ObfuscationRatio", "NoOfLettersInURL",
    "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
    # Word-level signals (added 2026-09-23): the 20 structural features
    # above can't "read" a URL, so .../account-update-login?verify=paypal
    # on an innocent-looking host scored as legitimate.
    "NoOfSuspiciousWords", "HasBrandOutsideDomain",
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


# Marketing/analytics parameters that sites append to ordinary links.
# They carry no information about whether the page is phishing, but they
# make a legitimate link long and full of "=", "&", "_" and digits - the
# exact lexical signals the model associates with phishing.
_TRACKING_PARAMS = {
    "fbclid", "gclid", "dclid", "gbraid", "wbraid", "msclkid", "yclid",
    "mc_cid", "mc_eid", "igshid", "_ga", "_gl", "ref", "ref_src", "ref_url",
    "spm", "scid", "si", "trk", "mkt_tok", "_hsenc", "_hsmi", "cmpid",
    "s_cid", "vero_id", "share", "feature",
}


def _is_tracking_param(name: str) -> bool:
    n = name.lower()
    return n in _TRACKING_PARAMS or n.startswith(("utm_", "oly_", "pk_"))


def strip_tracking(url: str) -> str:
    """Drop the #fragment and tracking query parameters (utm_*, fbclid,
    gclid, ...). Keeps every other parameter unchanged, so a phishing URL's
    real payload (?id=..&acct=..) is still measured."""
    parsed = urlparse(url)
    if not parsed.query and not parsed.fragment:
        return url
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    kept = [(k, v) for k, v in pairs if not _is_tracking_param(k)]
    # Re-encode only if something was removed, so untouched queries keep
    # their exact original characters.
    query = parsed.query if len(kept) == len(pairs) else urlencode(kept)
    return urlunparse(parsed._replace(query=query, fragment=""))


def canonicalize_url(url: str) -> str:
    """
    Ensure a scheme, strip a leading "www." host label, and remove the
    #fragment + tracking parameters (see strip_tracking).

    Training data (PhiUSIIL) recorded every legitimate URL as "www.<domain>"
    but phishing URLs inconsistently, so without this a bare domain like
    "chatgpt.com" reads as a strong phishing signal purely because it lacks
    "www." — a labeling artifact, not a real distinction. Canonicalizing
    here (used by both the lookup-table builders and compute_features)
    makes "www.example.com" and "example.com" score identically everywhere.
    """
    raw = url.strip()
    if not raw.lower().startswith(("http://", "https://")):
        raw = "http://" + raw

    parsed = urlparse(raw)
    netloc = parsed.netloc
    host = netloc.split("@")[-1].split(":")[0]
    if host.lower().startswith("www."):
        netloc = netloc[: len(netloc) - len(host)] + host[4:]
        parsed = parsed._replace(netloc=netloc)
        raw = urlunparse(parsed)

    raw = strip_tracking(raw)

    # Drop trailing slashes ("site.com/" -> "site.com", "/learn/" ->
    # "/learn"). In PhiUSIIL 31% of phishing URLs are "domain.com/" but 0%
    # of legitimate ones, so the model had learned "ends with / = phishing"
    # (https://www.google.com/ scored 84%) - a dataset artifact, not a real
    # signal.
    parsed = urlparse(raw)
    if parsed.path.endswith("/"):
        raw = urlunparse(parsed._replace(path=parsed.path.rstrip("/")))
    return raw


_SUSPICIOUS_WORDS = sorted(
    {w for w in CREDENTIAL_KEYWORDS + FINANCIAL_KEYWORDS if "-" not in w}
)
_BRAND_ALIASES = [
    (alias, meta["official_domains"])
    for meta in BRANDS.values() for alias in meta["aliases"]
]


def _tokens(text: str) -> list:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _word_in(word: str, tokens: list) -> bool:
    """Whole-token match; longer words may also start/end a token
    ("paypalsecure", "verification", "securelogin"). Short words must match
    exactly so "card" doesn't fire on "cardiff", and a word buried mid-token
    doesn't count ("designing" is not "signin")."""
    return any(
        t == word or (len(word) >= 5 and (t.startswith(word) or t.endswith(word)))
        for t in tokens
    )


def suspicious_word_count(raw: str) -> int:
    """Distinct credential/financial words (login, verify, account, bank,
    ...) anywhere after the scheme."""
    tokens = _tokens(raw.split("://", 1)[-1])
    return sum(_word_in(w, tokens) for w in _SUSPICIOUS_WORDS)


def brand_outside_domain(raw: str, host: str) -> int:
    """1 if a well-known brand name (paypal, maybank, amazon, ...) appears
    in the URL while the host is NOT that brand's official domain."""
    tokens = _tokens(raw.split("://", 1)[-1])
    return int(any(
        _word_in(alias, tokens) and not _is_official_host(host, official)
        for alias, official in _BRAND_ALIASES
    ))


def compute_features(url: str, tld_lookup: dict, char_lookup: dict) -> dict:
    """
    Pure function: compute the 22 URL features for a raw URL string
    using explicit lookup tables. Called by BOTH the training script
    and the inference path so the model sees identical feature values
    in both phases.
    """
    raw = canonicalize_url(url)

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
        # Neutral 0.5 prior for TLDs the training set never saw
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
        "SpacialCharRatioInURL": round(len(other_specials) / max(url_len, 1), 3),
        "IsHTTPS": int(parsed.scheme == "https"),
        "NoOfSuspiciousWords": suspicious_word_count(raw),
        "HasBrandOutsideDomain": brand_outside_domain(raw, host),
    }


def extract_features(url: str) -> dict:
    """Inference-side wrapper: uses module-level lookups loaded from disk."""
    _load_lookups()
    return compute_features(url, _TLD_LOOKUP, _CHAR_LOOKUP)


def feature_vector(url: str) -> np.ndarray:
    """Features as a (1, n) array in the exact order the model expects."""
    feats = extract_features(url)
    return np.array([[feats[name] for name in FEATURE_ORDER]])
