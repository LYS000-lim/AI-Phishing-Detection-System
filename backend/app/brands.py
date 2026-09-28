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
"""
import re

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


def impersonated_brand(url: str) -> "str | None":
    """Brand name found in the URL's hostname, or None. Callers must also
    check the domain is not well established (the brand's own sites are)."""
    host = _host(url)
    if not host:
        return None
    # Only the part of the hostname that is not itself a well-established
    # domain counts: amazonaws.com (Amazon's own platform) is not an Amazon
    # impersonation, but facebook-login.weebly.com is.
    reg = _extract_icann(host).top_domain_under_public_suffix
    rank = _load_ranks().get(reg)
    if reg and rank is not None and rank <= MAX_RANK:
        host = host[: -len(reg)]
    for brand, pattern in _PATTERNS:
        if pattern.search(host):
            return brand
    return None
