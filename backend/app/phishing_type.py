import re
from difflib import SequenceMatcher
from urllib.parse import urlparse


# Brand metadata is used only for explanatory analysis after the ML model has
# already classified a URL as phishing. It does not replace the ML decision.
BRANDS = {
    "Maybank": {
        "aliases": ("maybank", "maybank2u"),
        "official_domains": ("maybank.com.my", "maybank2u.com.my"),
        "financial": True,
    },
    "PayPal": {
        "aliases": ("paypal",),
        "official_domains": ("paypal.com",),
        "financial": True,
    },
    "CIMB": {
        "aliases": ("cimb", "cimbclicks"),
        "official_domains": ("cimb.com.my", "cimbclicks.com.my"),
        "financial": True,
    },
    "Public Bank": {
        "aliases": ("publicbank", "pbebank"),
        "official_domains": ("publicbank.com.my", "pbebank.com"),
        "financial": True,
    },
    "RHB": {
        "aliases": ("rhb", "rhbgroup"),
        "official_domains": ("rhbgroup.com",),
        "financial": True,
    },
    "Bank Islam": {
        "aliases": ("bankislam",),
        "official_domains": ("bankislam.com.my",),
        "financial": True,
    },
    "Google": {
        "aliases": ("google",),
        "official_domains": ("google.com",),
        "financial": False,
    },
    "Microsoft": {
        "aliases": ("microsoft", "outlook", "office365"),
        "official_domains": ("microsoft.com", "outlook.com", "office.com", "office365.com"),
        "financial": False,
    },
    "Apple": {
        "aliases": ("apple", "icloud"),
        "official_domains": ("apple.com", "icloud.com"),
        "financial": False,
    },
    "Facebook": {
        "aliases": ("facebook", "fb"),
        "official_domains": ("facebook.com",),
        "financial": False,
    },
    "Instagram": {
        "aliases": ("instagram",),
        "official_domains": ("instagram.com",),
        "financial": False,
    },
    "Amazon": {
        "aliases": ("amazon",),
        "official_domains": ("amazon.com",),
        "financial": False,
    },
}


CREDENTIAL_KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "password",
    "account", "auth", "authenticate", "secure-login", "security-check",
    "confirm", "update-account",
)

FINANCIAL_KEYWORDS = (
    "bank", "payment", "invoice", "billing", "wallet", "transaction",
    "money", "card", "credit", "debit",
)

GIVEAWAY_KEYWORDS = (
    "free", "winner", "winning", "gift", "reward", "prize", "claim",
    "bonus",
)

MALWARE_KEYWORDS = (
    "virus", "warning", "alert", "support", "download", "install",
    ".exe", "crack", "malware",
)

COMMON_SUBSTITUTIONS = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
})


def _normalise_url(url: str) -> str:
    raw = (url or "").strip()
    if raw and not raw.lower().startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw


def _host(url: str) -> str:
    try:
        return urlparse(_normalise_url(url)).netloc.lower().split(":")[0]
    except Exception:
        return ""


def _host_tokens(host: str) -> list[str]:
    return [p for p in re.split(r"[.\-_]+", host) if p]


def _is_official_host(host: str, official_domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in official_domains)


def _normalise_lookalike(text: str) -> str:
    return re.sub(r"[^a-z]", "", text.lower().translate(COMMON_SUBSTITUTIONS))


def _brand_analysis(host: str) -> dict:
    """Detect brand impersonation and simple typosquatting signals."""
    tokens = _host_tokens(host)
    findings = []

    for brand, meta in BRANDS.items():
        if _is_official_host(host, meta["official_domains"]):
            continue

        exact_alias = None
        typo_token = None

        for alias in meta["aliases"]:
            if alias in host:
                exact_alias = alias
                break

        if exact_alias is None:
            for token in tokens:
                normalized_token = _normalise_lookalike(token)
                for alias in meta["aliases"]:
                    normalized_alias = _normalise_lookalike(alias)
                    if not normalized_token:
                        continue
                    # A common character substitution can normalise exactly to
                    # the brand (for example paypa1 -> paypal).
                    if normalized_token == normalized_alias and token.lower() != alias.lower():
                        typo_token = token
                        break
                    if normalized_token == normalized_alias:
                        continue
                    ratio = SequenceMatcher(None, normalized_token, normalized_alias).ratio()
                    # High similarity plus similar length is a conservative
                    # lightweight typosquatting indicator.
                    if ratio >= 0.82 and abs(len(normalized_token) - len(normalized_alias)) <= 2:
                        typo_token = token
                        break
                if typo_token:
                    break

        if exact_alias or typo_token:
            findings.append({
                "brand": brand,
                "financial": meta["financial"],
                "exact_alias": exact_alias,
                "typo_token": typo_token,
            })

    # Prefer a financial brand when several brand-like strings are present.
    findings.sort(key=lambda x: (not x["financial"], x["brand"]))
    return findings[0] if findings else {}


def _present_keywords(url_lower: str, candidates: tuple[str, ...]) -> list[str]:
    return [word for word in candidates if word in url_lower]


def detect_phishing_type(url: str, features: dict) -> dict:
    """
    Produce human-readable phishing attack analysis for the UI.

    The ML model remains the source of the phishing/legitimate verdict. This
    function only labels observable attack patterns after a phishing verdict.

    Returned keys intentionally keep ``category`` and ``reason`` for backward
    compatibility with the current frontend while adding the cleaner
    ``techniques`` and ``indicators`` fields needed by the redesigned UI.
    """
    url_lower = (url or "").lower()
    host = _host(url)

    credential_hits = _present_keywords(url_lower, CREDENTIAL_KEYWORDS)
    financial_hits = _present_keywords(url_lower, FINANCIAL_KEYWORDS)
    giveaway_hits = _present_keywords(url_lower, GIVEAWAY_KEYWORDS)
    malware_hits = _present_keywords(url_lower, MALWARE_KEYWORDS)
    brand = _brand_analysis(host)

    techniques: list[str] = []
    indicators: list[str] = []

    # ------------------------- Category -------------------------
    if brand.get("financial") or financial_hits:
        category = "Financial Scam"
    elif len(credential_hits) >= 2:
        category = "Credential Theft"
    elif giveaway_hits:
        category = "Fake Giveaway / Scam"
    elif malware_hits:
        category = "Tech Support / Malware Scam"
    else:
        category = "Domain Spoofing / Brand Impersonation"

    # ------------------------- Techniques -----------------------
    if brand:
        techniques.append("Brand Impersonation")
        brand_name = brand["brand"]
        if brand.get("financial"):
            indicators.append(
                f'The URL contains the financial brand "{brand_name}", which may '
                "indicate an attempt to imitate a banking or payment service."
            )
        else:
            indicators.append(
                f'The URL contains the trusted brand "{brand_name}", which may '
                "indicate an attempt to imitate a legitimate service."
            )

        if brand.get("typo_token"):
            techniques.append("Typosquatting")
            indicators.append(
                f'The text "{brand["typo_token"]}" appears visually similar to '
                f'the trusted brand "{brand_name}".'
            )

    if credential_hits:
        # Keep Brand Impersonation as the primary technique when present. Add
        # credential harvesting only when it provides distinct information.
        if not brand:
            techniques.append("Credential Harvesting")
        shown = credential_hits[:3]
        quoted = ", ".join(f'"{w}"' for w in shown)
        if brand:
            indicators.append(
                f'The brand name "{brand["brand"]}" appears together with '
                f"suspicious account or verification wording such as {quoted}."
            )
        else:
            indicators.append(
                f"The URL contains credential-related wording such as {quoted}, "
                "which may be used to lure users into submitting account details."
            )

    # A malware/support URL can use more than one technique at the same time.
    # Keep the category separate, but accumulate the observable techniques so a
    # URL such as virus-warning.../download/...exe can be described as both a
    # fake security alert and a malware-delivery lure.
    if malware_hits:
        alert_terms = {"virus", "warning", "alert", "support"}
        delivery_terms = {"download", "install", ".exe", "crack", "malware"}

        if any(term in malware_hits for term in alert_terms):
            techniques.append("Fake Security Alert")
            shown_alerts = [term for term in malware_hits if term in alert_terms][:3]
            quoted_alerts = ", ".join(f'"{w}"' for w in shown_alerts)
            indicators.append(
                f"The URL uses security-warning or support wording such as {quoted_alerts}, "
                "which may be used to pressure a user into taking unsafe action."
            )

        if any(term in malware_hits for term in delivery_terms):
            techniques.append("Malware Delivery")
            shown_delivery = [term for term in malware_hits if term in delivery_terms][:3]
            quoted_delivery = ", ".join(f'"{w}"' for w in shown_delivery)
            indicators.append(
                f"The URL contains download or executable-related wording such as {quoted_delivery}, "
                "which may indicate an attempt to deliver malicious software."
            )

    if features.get("HasObfuscation") == 1:
        techniques.append("URL Obfuscation")
        indicators.append(
            "The URL contains obfuscation patterns that can make the real address harder to recognise."
        )

    if features.get("IsDomainIP") == 1:
        techniques.append("IP Address Hosting")
        indicators.append(
            "The website uses an IP address instead of a normal domain name."
        )

    if features.get("NoOfSubDomain", 0) >= 3:
        indicators.append(
            "The URL contains multiple subdomains, a structure that can be used to disguise the real registered domain."
        )

    if not techniques:
        techniques.append("Suspicious URL Pattern")

    if not indicators:
        indicators.append(
            "The URL contains structural characteristics that contributed to the phishing prediction."
        )

    # Remove duplicates while preserving display order.
    techniques = list(dict.fromkeys(techniques))[:3]
    indicators = list(dict.fromkeys(indicators))[:4]

    return {
        "category": category,
        "techniques": techniques,
        "technique": " / ".join(techniques),
        "indicators": indicators,
        # Backward-compatible field used by the original Scanner.jsx.
        "reason": indicators,
        "brand": brand.get("brand"),
        "keywords": credential_hits[:3] + financial_hits[:2],
    }
