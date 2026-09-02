"""
Curated allowlist of high-reputation domains.

Real-world phishing detection systems (Google Safe Browsing, VirusTotal,
Microsoft SmartScreen, Cisco Umbrella, etc.) all combine ML classifiers
with reputation lists. This module implements the reputation-list side.

Why it exists:
- Datasets like PhiUSIIL were collected at a specific point in time. New
  legitimate domains (chatgpt.com, claude.ai, ...) were not in the
  training set, so the URL-only ML model has never seen their character
  distribution and can misclassify them as phishing.
- False positives on obviously-legitimate URLs damage user trust more
  than an occasional missed phishing URL, so top-tier domains SHOULD
  bypass ML classification.
- The list is intentionally small and only holds domains most users
  would recognise as trustworthy. Everything else still goes through
  the ML pipeline.

If you want to expand or shrink this list at deploy time, edit
TRUSTED_DOMAINS below. In a bigger production system this would live
in a database or a config file loaded on startup.
"""

from urllib.parse import urlparse

# Registrable domains (no protocol, no path). Subdomains match automatically:
# "mail.google.com" is trusted because "google.com" is on the list.
TRUSTED_DOMAINS = {
    # Search engines and AI assistants
    "google.com", "bing.com", "duckduckgo.com", "yahoo.com", "yandex.com",
    "baidu.com", "ecosia.org", "brave.com", "startpage.com",
    "chatgpt.com", "openai.com", "claude.ai", "anthropic.com",
    "perplexity.ai", "poe.com", "character.ai", "midjourney.com",
    "gemini.google.com", "copilot.microsoft.com", "huggingface.co",

    # Social platforms
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "tiktok.com", "pinterest.com",
    "snapchat.com", "youtube.com", "whatsapp.com", "telegram.org",
    "signal.org", "discord.com", "threads.net", "mastodon.social",
    "bluesky.social", "quora.com", "tumblr.com",

    # Developer tools and hosting
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "stackexchange.com", "npmjs.com", "pypi.org", "rubygems.org",
    "packagist.org", "crates.io", "hex.pm", "nuget.org", "maven.org",
    "docker.com", "docker.io", "kubernetes.io", "helm.sh",
    "cloudflare.com", "vercel.com", "netlify.com", "heroku.com",
    "digitalocean.com", "linode.com", "aws.amazon.com", "azure.com",
    "cloud.google.com", "render.com", "railway.app", "supabase.com",
    "firebase.google.com", "mongodb.com", "redis.io", "postgresql.org",

    # Big tech
    "apple.com", "icloud.com", "microsoft.com", "adobe.com",
    "oracle.com", "ibm.com", "intel.com", "nvidia.com", "amd.com",
    "samsung.com", "sony.com", "lg.com", "hp.com", "dell.com",
    "lenovo.com", "asus.com", "acer.com", "huawei.com", "xiaomi.com",

    # Productivity and communication
    "gmail.com", "outlook.com", "office.com", "office365.com",
    "onedrive.live.com", "sharepoint.com", "teams.microsoft.com",
    "meet.google.com", "zoom.us", "slack.com", "notion.so",
    "trello.com", "asana.com", "monday.com", "atlassian.com",
    "clickup.com", "airtable.com", "miro.com", "figma.com",
    "canva.com", "dropbox.com", "box.com", "wetransfer.com",

    # E-commerce
    "amazon.com", "ebay.com", "walmart.com", "target.com", "shopify.com",
    "etsy.com", "aliexpress.com", "alibaba.com", "lazada.com",
    "shopee.com", "shopee.com.my", "lazada.com.my", "zalora.com",
    "bestbuy.com", "costco.com", "wayfair.com", "wish.com",

    # Education and reference
    "wikipedia.org", "wikimedia.org", "mit.edu", "harvard.edu",
    "stanford.edu", "cambridge.org", "ox.ac.uk", "berkeley.edu",
    "khanacademy.org", "coursera.org", "udemy.com", "edx.org",
    "duolingo.com", "brilliant.org", "codecademy.com", "freecodecamp.org",
    "w3schools.com", "developer.mozilla.org", "mdn.io",

    # News and media
    "nytimes.com", "bbc.com", "bbc.co.uk", "cnn.com", "theguardian.com",
    "reuters.com", "bloomberg.com", "wsj.com", "ft.com", "economist.com",
    "medium.com", "substack.com", "wired.com", "techcrunch.com",
    "arstechnica.com", "theverge.com",

    # Financial and payments
    "paypal.com", "stripe.com", "wise.com", "revolut.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "hsbc.com", "barclays.co.uk", "santander.com",

    # Streaming and entertainment
    "netflix.com", "spotify.com", "twitch.tv", "hulu.com", "disney.com",
    "disneyplus.com", "hbomax.com", "primevideo.com", "vimeo.com",
    "soundcloud.com", "bandcamp.com", "steam.com", "steampowered.com",
    "epicgames.com", "playstation.com", "xbox.com", "nintendo.com",

    # Malaysia-relevant (client is a Malaysian student)
    "maybank.com.my", "maybank2u.com.my", "cimb.com.my", "cimbclicks.com.my",
    "publicbank.com.my", "pbebank.com", "rhbgroup.com", "hongleongbank.com.my",
    "ambank.com.my", "affinbank.com.my", "bankislam.com.my",
    "grab.com", "airasia.com", "malaysiaairlines.com",
    "utar.edu.my", "um.edu.my", "usm.my", "sunway.edu.my",
    "monash.edu.my", "taylors.edu.my", "mmu.edu.my", "help.edu.my",
    "gov.my", "myeg.com.my", "lhdn.gov.my", "epf.gov.my", "kwsp.gov.my",

    # Common TLDs for national/gov sites often flagged incorrectly
    "gov.uk", "gov.au", "gov.sg", "gov.in", "canada.ca",
}

# Common two-level TLDs that need special handling when extracting the
# registrable domain (e.g. amazon.co.uk -> amazon.co.uk, not co.uk).
_TWO_LEVEL_TLDS = {
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz",
    "com.my", "com.sg", "com.au", "com.br", "com.mx", "com.tr",
    "com.hk", "com.tw", "com.ph", "com.vn", "com.pk", "com.bd",
    "net.au", "org.au", "gov.uk", "ac.uk", "gov.au", "gov.sg",
    "gov.my", "gov.in", "gov.hk",
}


def _registrable_domain(host: str) -> str:
    """
    Extract the registrable domain from a host string.

    Examples:
        www.google.com          -> google.com
        mail.google.com         -> google.com
        chatgpt.com             -> chatgpt.com
        amazon.co.uk            -> amazon.co.uk
        www.amazon.co.uk        -> amazon.co.uk
    """
    host = (host or "").lower().strip().split(":")[0]  # strip port
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) < 2:
        return host

    last_two = ".".join(parts[-2:])
    # Handle two-level public suffixes like ".co.uk", ".com.my"
    if len(parts) >= 3 and last_two in _TWO_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return last_two


def is_trusted(url: str) -> bool:
    """
    Return True if the URL's registrable domain is on the trusted
    allowlist. Handles URLs with or without a scheme.
    """
    if not url:
        return False
    try:
        raw = url.strip()
        if not raw.lower().startswith(("http://", "https://")):
            raw = "http://" + raw
        host = urlparse(raw).netloc
        return _registrable_domain(host) in TRUSTED_DOMAINS
    except Exception:
        return False


def matched_domain(url: str) -> str:
    """Return the trusted domain that matched, or empty string if none."""
    if not url:
        return ""
    try:
        raw = url.strip()
        if not raw.lower().startswith(("http://", "https://")):
            raw = "http://" + raw
        reg = _registrable_domain(urlparse(raw).netloc)
        return reg if reg in TRUSTED_DOMAINS else ""
    except Exception:
        return ""
