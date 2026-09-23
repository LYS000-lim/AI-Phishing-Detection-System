"""
Domain reputation layer (runs AFTER the ML model).

Problem it solves: the model only sees URL text, so a real login page such
as login.microsoftonline.com/.../authorize?client_id=... looks exactly like
a phishing login page. What actually separates them is WHO OWNS THE DOMAIN,
which URL text cannot show.

Rule: if the URL's registered domain is among the most popular websites in
the Tranco list (research-grade ranking, https://tranco-list.eu), a
"phishing" verdict is capped at "suspicious" - the user is still warned,
but a well-established site is never accused outright. It never turns a
result into "legitimate"; that is only the curated allowlist's job.

Popular platforms where ANYONE can publish content (free hosting, cloud
storage, IPFS gateways, form builders...) are excluded, because attackers
host phishing there. Two mechanisms:
  1. tldextract with the Public Suffix List's PRIVATE section: e.g.
     evil.web.app / evil.github.io / evil.blogspot.com resolve to their own
     registered domain, which is not ranked, so they get no reputation.
  2. HOSTING_PLATFORMS below, for platforms not on the Public Suffix List
     (found by checking which popular domains host PhiUSIIL / OpenPhish
     phishing).
"""
import csv
import os
from urllib.parse import urlparse

import joblib
import tldextract

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..", "..")
_CACHE = os.path.join(_ROOT, "outputs", "tranco_rank.joblib")
_TRANCO_CSV = os.path.join(_ROOT, "top-1m.csv")

# Domains ranked within this many positions count as "reputable".
# Chosen with backend/tests/realworld_eval.py (see the report there).
MAX_RANK = 250_000

# Offline: uses tldextract's bundled Public Suffix List snapshot (no
# network call at runtime).
_extract_private = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_extract_icann = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

HOSTING_PLATFORMS = {
    # site builders / free hosting
    "weebly.com", "weeblysite.com", "wixsite.com", "wix.com", "square.site",
    "godaddysites.com", "webflow.io", "carrd.co", "strikingly.com",
    "jimdosite.com", "site123.me", "mystrikingly.com", "yolasite.com",
    "000webhostapp.com", "000webhost.com", "wordpress.com", "blogger.com",
    "tumblr.com", "notion.site", "gitbook.io", "framer.app", "framer.website",
    "repl.co", "replit.app", "replit.dev", "glitch.me", "pantheonsite.io",
    "xsph.ru", "tw1.ru", "regruhosting.ru", "cprapid.com", "hostingersite.com",
    "infinityfreeapp.com", "rf.gd", "epizy.com", "byethost.com",
    # cloud / serverless / object storage
    "workers.dev", "pages.dev", "r2.dev", "amazonaws.com", "cloudfront.net",
    "windows.net", "azurewebsites.net", "azureedge.net", "web.core.windows.net",
    "googleapis.com", "appspot.com", "firebaseapp.com", "web.app",
    "netlify.app", "vercel.app", "onrender.com", "herokuapp.com",
    "github.io", "gitlab.io", "surge.sh", "fly.dev", "railway.app",
    "digitaloceanspaces.com", "backblazeb2.com", "wasabisys.com",
    # IPFS / decentralised gateways
    "ipfs.io", "dweb.link", "cf-ipfs.com", "pinata.cloud", "w3s.link",
    "fleek.co", "4everland.io", "nftstorage.link",
    # file sharing / forms / docs / link-in-bio / short links
    "dropbox.com", "dropboxusercontent.com", "box.com", "mediafire.com",
    "wetransfer.com", "sharepoint.com", "onedrive.live.com", "1drv.ms",
    "forms.gle", "jotform.com", "typeform.com", "formstack.com",
    "linktr.ee", "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "ow.ly", "rb.gy", "qrco.de",
    # found on popular domains in PhiUSIIL phishing (sample, top-250k check)
    "webwave.dev", "myportfolio.com", "infura-ipfs.io", "myqcloud.com",
    "aliyuncs.com", "swtest.ru", "usrfiles.com", "publicvm.com", "start.page",
    "s.id", "myhuaweicloud.com", "work.gd", "webcindario.com", "temp-site.link",
    "cloudwaysapps.com", "codeanyapp.com", "short.gy", "selcdn.ru",
    "oraclecloud.com", "beget.tech", "cloudclusters.net", "arweave.net",
    "free.fr", "ic0.app", "zzz.com.ua", "urlz.fr", "myftpupload.com",
    "secureserver.net", "wpengine.com", "tmweb.ru", "1gb.ru", "dynadot.com",
    "crazydomains.com", "bio.site", "preview-domain.com",
    # dynamic DNS / tunnels (incl. ChangeIP free domains)
    "itsaol.com", "zzux.com", "yourtrap.com", "longmusic.com", "2waky.com",
    "duckdns.org", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com",
    "serveo.net", "no-ip.com", "ddns.net", "hopto.org", "zapto.org",
}

# Specific subdomains of otherwise-reputable companies where users publish
# content (docs.google.com forms, sites.google.com pages, ...).
HOSTING_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "script.google.com",
    "storage.cloud.google.com", "forms.office.com", "forms.microsoft.com",
    "onedrive.live.com", "1drv.ms", "sway.office.com", "gamma.app",
}


def is_user_content_host(url: str) -> bool:
    """True for hosts where anyone can publish pages (platform domains and
    user-content subdomains of big companies). Used by the allowlist too,
    so "google.com is trusted" never extends to sites.google.com pages."""
    host = _host(url)
    if not host:
        return False
    icann_reg = _extract_icann(host).top_domain_under_public_suffix
    private_reg = _extract_private(host).top_domain_under_public_suffix
    return (
        private_reg != icann_reg
        or icann_reg in HOSTING_PLATFORMS
        or any(host == h or host.endswith("." + h) for h in HOSTING_HOSTS)
    )

_ranks = None


def _load_ranks() -> dict:
    """registered domain -> Tranco rank, limited to the top 1M. Cached as
    outputs/tranco_rank.joblib so the 1M-row CSV isn't needed at runtime."""
    global _ranks
    if _ranks is None:
        if os.path.exists(_CACHE):
            _ranks = joblib.load(_CACHE)
        elif os.path.exists(_TRANCO_CSV):
            with open(_TRANCO_CSV, encoding="utf-8") as fh:
                _ranks = {row[1].lower(): int(row[0]) for row in csv.reader(fh)}
            joblib.dump(_ranks, _CACHE, compress=3)
        else:
            _ranks = {}
    return _ranks


def _host(url: str) -> str:
    raw = (url or "").strip()
    if not raw.lower().startswith(("http://", "https://")):
        raw = "http://" + raw
    return (urlparse(raw).hostname or "").lower()


def domain_reputation(url: str, max_rank: int = MAX_RANK) -> dict:
    """
    {"reputable": bool, "domain": registered domain, "rank": int|None,
     "reason": short explanation}
    """
    host = _host(url)
    private_reg = _extract_private(host).top_domain_under_public_suffix if host else ""
    icann_reg = _extract_icann(host).top_domain_under_public_suffix if host else ""
    out = {"reputable": False, "domain": icann_reg or host, "rank": None, "reason": ""}
    if not icann_reg:
        out["reason"] = "no registered domain (IP address or local host)"
        return out
    if is_user_content_host(url):
        out["reason"] = f"hosted on a shared platform ({icann_reg}) where anyone can publish"
        return out
    rank = _load_ranks().get(icann_reg)
    out["rank"] = rank
    if rank is not None and rank <= max_rank:
        out["reputable"] = True
        out["reason"] = f"{icann_reg} is a well-established website (Tranco rank #{rank:,})"
    else:
        out["reason"] = f"{icann_reg} is not among the top {max_rank:,} websites"
    return out
