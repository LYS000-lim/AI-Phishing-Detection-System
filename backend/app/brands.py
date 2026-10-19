"""
Brand-impersonation rule (runs AFTER the ML model, like reputation.py).

Problem: on phishing first seen after training (OpenPhish/phishunt,
2026-09-27) many misses put a brand in their own domain name -
facebook.net.tw, appeal-coinbase.com, privacy-trezor.io, roblox.com.pt.
The model's HasBrandOutsideDomain feature only knows the 12 brands in
phishing_type.BRANDS, and extending that list would change a model feature
(retrain needed).

How the list was built (training-period data only, never the test URLs):
  1. candidate = the name label of a Tranco top-20k domain (roblox.com ->
     "roblox"), letters only, >= 5 characters
  2. found in >= 150 distinct 2024-25 Phishing.Database hosts that are not
     the brand's own domain, and >= 10x more often than inside other
     top-1M domains (notebooks/harvest_phish_feeds.py data)
  3. manual review removed generic words and hosting services (login,
     account, verify, customer, alerts, blogspot, cloudns, ...)

Rule: a brand in the hostname of a domain that is NOT well established
(reputation.py: Tranco top MAX_RANK) raises the verdict one step. The
brand's real sites are all top-ranked, so they are never affected.

Look-alike spellings of these names are handled by lookalike_brand() below.
"""
import re
import unicodedata

from .phishing_type import BRANDS as MODEL_BRANDS
from .reputation import MAX_RANK, _extract_icann, _host, _load_ranks

# Ordered by number of 2024-25 phishing hosts impersonating the brand.
FEED_BRANDS = (
    "facebook", "whatsapp", "amazon", "apple", "coinbase", "instagram", "metamask",
    "telegram", "trezor", "ledger", "netflix", "yahoo", "paypal", "codashop", "chase",
    "icloud", "garena", "microsoft", "wellsfargo", "opensea", "rakuten", "outlook",
    "binance", "bancolombia", "discord", "kraken", "tiktok", "exodus", "airbnb",
    "santander", "robinhood", "kucoin", "gemini", "allegro", "walletconnect",
    "btinternet", "trustwallet", "telstra", "allegrolokalnie", "royalmail",
    "steamcommunity", "spotify", "vidio", "midasbuy", "uniswap", "fidelity",
    "twitter", "pubgmobile", "adobe", "krafton", "hotmail", "biglobe", "caixa",
    "microsoftonline", "mercari", "mygov", "ionos", "rogers", "commbank",
    "leboncoin", "bankofamerica", "lloydsbank", "americanas", "avira", "docusign",
    "huntington", "bellsouth", "sbcglobal", "linkedin", "naver", "snapchat",
    "runescape", "xfinity", "craigslist",
)
_DISPLAY = {
    "whatsapp": "WhatsApp", "metamask": "MetaMask", "icloud": "iCloud", "paypal": "PayPal",
    "wellsfargo": "Wells Fargo", "opensea": "OpenSea", "tiktok": "TikTok",
    "walletconnect": "WalletConnect", "btinternet": "BT Internet", "trustwallet": "Trust Wallet",
    "allegrolokalnie": "Allegro", "royalmail": "Royal Mail", "steamcommunity": "Steam",
    "pubgmobile": "PUBG Mobile", "microsoftonline": "Microsoft", "mygov": "myGov",
    "commbank": "CommBank", "bankofamerica": "Bank of America", "lloydsbank": "Lloyds Bank",
    "docusign": "DocuSign", "bellsouth": "BellSouth", "sbcglobal": "SBCGlobal",
    "linkedin": "LinkedIn", "kucoin": "KuCoin", "runescape": "RuneScape",
}
FINANCIAL = {
    "coinbase", "metamask", "trezor", "ledger", "paypal", "chase", "wellsfargo", "opensea",
    "binance", "bancolombia", "kraken", "exodus", "santander", "robinhood", "kucoin",
    "gemini", "walletconnect", "trustwallet", "uniswap", "fidelity", "caixa", "commbank",
    "bankofamerica", "lloydsbank", "huntington",
}


def display_name(brand: str) -> str:
    return _DISPLAY.get(brand, brand.capitalize())


# Short names that are also parts of ordinary words (purchase -> "chase",
# pineapple -> "apple") must stand alone between separators; longer names
# are matched anywhere, since phishers glue them to other words
# (coinbaselogn, xfinityloginxfinity).
_MIN_SUBSTRING_LEN = 6
# Brand names that are also ordinary words or word endings - found inside
# legitimate Tranco domains (worldenergyoutlook.org, hledger.org,
# survivinginfidelity.com, opticloud.de, royrogersrestaurants.com).
_WORD_BRANDS = {"icloud", "outlook", "ledger", "fidelity", "rogers", "gemini",
                "exodus", "kraken", "allegro", "caixa"}
_BOUNDARY = r"(?<![a-z]){}(?![a-z])"
_PATTERNS = [
    (b, re.compile(_BOUNDARY.format(re.escape(b))
                   if len(b) < _MIN_SUBSTRING_LEN or b in _WORD_BRANDS else re.escape(b)))
    for b in FEED_BRANDS
]


# ---------------------------------------------------------------------------
# Malaysian brands
# ---------------------------------------------------------------------------
# Hand-curated for the system's Malaysian users (NOT mined from the feeds
# like FEED_BRANDS): banks, e-wallets, couriers, shops and government
# agencies named in common Malaysian scams, plus DHL and FedEx, which the
# mining step missed only because their names are shorter than 5 letters
# (2024-25 feeds: 1,787 and 100 phishing hosts). Generic words and
# acronyms with many unrelated owners (boost, unifi, maxis, epf, jpn, tng,
# bsn) were left out. Unlike the global brands, several official Malaysian
# sites rank below the Tranco top 250,000 (publicbank.com.my, rhb.com.my,
# ambank.com.my), so each name lists its official domains, which never
# count as impersonation; agency names also accept any .gov.my host.
# name: (pattern, display name, official domains)
_GOV = ".gov.my"
MY_BRANDS = {
    "maybank": (r"maybank", "Maybank", (
        "maybank.com", "maybank.com.my", "maybank2u.com.my", "maybank.com.sg", "maybank2u.com.sg",
        "maybank.co.th", "maybank.co.id", "maybankfinance.co.id", "maybank2eservice.com.my")),
    "cimb": (r"(?<![a-z])cimb(?![a-z])|cimbclicks", "CIMB", (
        "cimb.com", "cimb.com.my", "cimbclicks.com.my", "cimb.com.sg", "cimbbank.com.sg")),
    "publicbank": (r"(?<![a-z])public-?bank|pbebank", "Public Bank", (
        "publicbank.com.my", "publicbank.com.vn", "publicbank.com.hk", "pbebank.com",
        "publicislamicbank.com.my")),
    "rhb": (r"(?<![a-z])rhb(?![a-z])", "RHB", ("rhbgroup.com", "rhb.com.my")),
    "hongleong": (r"hong-?leong", "Hong Leong Bank", (
        "hlb.com.my", "hongleongbank.com.my", "hongleongconnect.com.my", "hongleongconnect.my",
        "hongleong.com.my")),
    "ambank": (r"(?<![a-z])ambank", "AmBank", ("ambank.com.my", "amonline.com.my", "ambankgroup.com")),
    "bankislam": (r"bank-?islam(?![a-z])", "Bank Islam", ("bankislam.com", "bankislam.com.my", "bankislam.biz")),
    "mybsn": (r"mybsn", "BSN", ("bsn.com.my", "mybsn.com.my")),
    "touchngo": (r"touch-?n-?go|tng-?digital", "Touch 'n Go", ("touchngo.com.my", "touchngo.com", "tngdigital.com.my")),
    "shopee": (r"shopee", "Shopee", (
        "shopee.com", "shopee.com.my", "shopee.sg", "shopee.co.id", "shopee.vn", "shopee.co.th",
        "shopee.ph", "shopee.tw", "shopee.com.br", "shopee.com.mx", "shopee.com.co", "shopee.cl",
        "shopee.pl", "shopee.es", "shopee.fr", "shopee.in", "shopeepay.com.my", "shopeepay.tw",
        "shopeemobile.com", "shopeekredit.co.id", "shopeefood.co.id", "shopeexpress.com.br")),
    "lazada": (r"lazada", "Lazada", (
        "lazada.com", "lazada.com.my", "lazada.sg", "lazada.co.id", "lazada.co.th", "lazada.vn",
        "lazada.com.ph")),
    "poslaju": (r"pos-?laju", "Pos Laju", ("pos.com.my", "poslaju.com.my")),
    "dhl": (r"(?<![a-z])dhl(?![a-z])", "DHL", (
        "dhl", "dhl.com", "dhl.com.my", "dhl.de", "dhl.co.uk", "dhl.com.pl", "dhl-usa.com",
        "dhl-freight-connections.com")),
    "fedex": (r"(?<![a-z])fedex(?![a-z])", "FedEx", ("fedex", "fedex.com", "fedex.com.cn")),
    "lhdn": (r"(?<![a-z])(lhdn|hasil)(?![a-z])", "LHDN (Inland Revenue Board)", (_GOV,)),
    "jpj": (r"(?<![a-z])jpj(?![a-z])", "JPJ (Road Transport Department)", (_GOV,)),
    "kwsp": (r"kwsp", "KWSP (EPF)", (_GOV,)),
    "pdrm": (r"(?<![a-z])pdrm(?![a-z])", "PDRM (Royal Malaysia Police)", (_GOV,)),
    "mysejahtera": (r"my-?sejahtera", "MySejahtera", (_GOV,)),
    "ptptn": (r"ptptn", "PTPTN", (_GOV,)),
    "perkeso": (r"perkeso", "PERKESO (SOCSO)", (_GOV,)),
    "petronas": (r"petronas", "Petronas", (
        "petronas.com", "petronas.com.my", "mymesra.com.my", "petronastwintowers.com.my")),
    "celcom": (r"(?<![a-z])celcom", "Celcom", ("celcom.com.my", "celcom.net.my", "celcomdigi.com")),
}
_MY_PATTERNS = [(name, re.compile(spec[0])) for name, spec in MY_BRANDS.items()]
MY_FINANCIAL = {"maybank", "cimb", "publicbank", "rhb", "hongleong", "ambank", "bankislam",
                "mybsn", "touchngo", "lhdn", "kwsp", "ptptn"}


def _is_official(host: str, official) -> bool:
    return any(host == d or host.endswith("." + d) or (d.startswith(".") and host.endswith(d))
               for d in official)


def malaysian_brand(url: str) -> "str | None":
    """Malaysian brand name found in the hostname of a site that is not one
    of the brand's official domains, or None. Callers must also check the
    domain is not well established."""
    host = _host(url)
    if not host:
        return None
    part = _unranked_part(host)
    for name, pattern in _MY_PATTERNS:
        if pattern.search(part) and not _is_official(host, MY_BRANDS[name][2]):
            return name
    return None


def _unranked_part(host: str) -> str:
    """The hostname without its registered domain when that domain is well
    established: amazonaws.com (Amazon's own platform) is not an Amazon
    impersonation, but facebook-login.weebly.com is."""
    reg = _extract_icann(host).top_domain_under_public_suffix
    rank = _load_ranks().get(reg)
    if reg and rank is not None and rank <= MAX_RANK:
        return host[: -len(reg)]
    return host


def impersonated_brand(url: str) -> "str | None":
    """Brand name found in the URL's hostname, or None. Callers must also
    check the domain is not well established (the brand's own sites are)."""
    host = _host(url)
    if not host:
        return None
    host = _unranked_part(host)
    for brand, pattern in _PATTERNS:
        if pattern.search(host):
            return brand
    return None


# ---------------------------------------------------------------------------
# Look-alike spellings (typosquatting)
# ---------------------------------------------------------------------------
# impersonated_brand() needs the exact spelling, so g00gle.com, paypa1.com
# and micros0ft.com passed as legitimate: the model scores them like any
# short, clean .com domain. lookalike_brand() checks the brand names above
# plus the brands of the model's own brand feature (phishing_type.BRANDS)
# for two kinds of imitation:
#   "characters"  - digits or letter pairs that imitate letters (0->o,
#                   1->l or i, 3->e, 4->a, 5->s, 7->t, rn->m, vv->w), or an
#                   internationalised (punycode) name whose characters
#                   imitate Latin letters, spell the brand. This has no
#                   innocent use, so classify_vec makes the verdict Phishing.
#   "misspelling" - one letter added, dropped, changed or swapped (gooogle,
#                   linkedln, whatsap). A few real names are one letter away
#                   from a brand (mybank.cn, huntingdon.edu), so this raises
#                   the verdict one step, like an exact brand name.
# Measured on the 750,000 Tranco domains ranked 250,001-1,000,000 (the
# rule never applies to the top 250,000): 150 matched (0.02%), most of them
# typo domains themselves (faceook.com, goolge.com, hotmial.com).
_ALIAS_DISPLAY = {alias: name for name, meta in MODEL_BRANDS.items() for alias in meta["aliases"]}
_FINANCIAL_ALIASES = {alias for meta in MODEL_BRANDS.values() if meta["financial"]
                      for alias in meta["aliases"]}
# Longest first, so maybank2u is reported rather than maybank.
_LOOKALIKE_NAMES = sorted({b for b in set(FEED_BRANDS) | set(_ALIAS_DISPLAY) if len(b) >= 4},
                          key=len, reverse=True)
_DIGIT_LETTERS = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t"}
# Cyrillic and Greek letters that look like Latin ones (homograph attacks).
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u04cf": "l",
    "\u0501": "d", "\u0455": "s", "\u04bb": "h", "\u051d": "w", "\u0261": "g",
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03b9": "i", "\u03ba": "k",
    "\u03bd": "v", "\u03c4": "t", "\u03c5": "u", "\u03b5": "e", "\u0131": "i",
})


def brand_display(alias: str) -> str:
    """Display name for a FEED_BRANDS or MY_BRANDS name or a
    phishing_type.BRANDS alias."""
    if alias in MY_BRANDS:
        return MY_BRANDS[alias][1]
    if alias in FEED_BRANDS:
        return display_name(alias)
    return _ALIAS_DISPLAY.get(alias) or display_name(alias)


def is_financial(alias: str) -> bool:
    return alias in FINANCIAL or alias in _FINANCIAL_ALIASES or alias in MY_FINANCIAL


def _decode_label(label: str):
    """(label with look-alike Unicode letters mapped to Latin, changed?)
    for a punycode (xn--) label; other labels are returned unchanged."""
    if not label.startswith("xn--"):
        return label, False
    try:
        text = label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return label, False
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c)).lower()
    return text.translate(_CONFUSABLES), True


def _character_variants(token: str) -> set:
    """The token with look-alike digits and letter pairs replaced."""
    base = "".join(_DIGIT_LETTERS.get(c, c) for c in token).replace("rn", "m").replace("vv", "w")
    return {base.replace("1", "l"), base.replace("1", "i")} - {token}


def _one_edit(a: str, b: str) -> bool:
    """True if a and b differ by exactly one inserted, deleted, changed or
    swapped (adjacent) letter."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (
            len(diff) == 2 and diff[1] == diff[0] + 1
            and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def lookalike_brand(url: str) -> "tuple | None":
    """(brand, imitating text, kind) when the URL's hostname imitates a
    brand name without spelling it exactly, else None. kind is "characters"
    or "misspelling" (see above). Callers must also check the domain is not
    well established."""
    host = _host(url)
    if not host:
        return None
    # (text to compare, shown as) - a punycode label is shown as written
    # (xn--...), since its decoded form looks exactly like the brand.
    tokens = []
    for label in _unranked_part(host).split("."):
        text, from_idn = _decode_label(label)
        tokens += [(t, label if from_idn else t, from_idn)
                   for t in re.split(r"[^a-z0-9]+", text) if len(t) >= 4]
    for token, shown, from_idn in tokens:
        for brand in _LOOKALIKE_NAMES:
            if from_idn and (token == brand or (len(brand) >= 5 and brand in token)):
                return brand, shown, "characters"
            # Ordinary words count only as punycode look-alikes: 1cloud.fm is a
            # real name, not an iCloud imitation.
            if brand in token or brand in _WORD_BRANDS:
                continue
            for variant in _character_variants(token):
                if variant == brand or (len(brand) >= 6 and brand in variant):
                    return brand, shown, "characters"
    for token, shown, _ in tokens:
        for brand in _LOOKALIKE_NAMES:
            if (len(brand) >= 6 and brand not in _WORD_BRANDS and brand not in token
                    and token[0] == brand[0] and _one_edit(token, brand)):
                return brand, shown, "misspelling"
    return None
