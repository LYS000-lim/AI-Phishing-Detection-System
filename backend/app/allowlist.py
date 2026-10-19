from urllib.parse import parse_qsl, urlparse

# SECURITY NOTE: this is a hard bypass -- a registrable-domain STRING match,
# nothing else (no TLS/cert check, no content check, no live lookup). A
# match skips the ML model entirely and returns "legitimate" outright, so
# treat it as a convenience shortcut for well-known domains, not a security
# guarantee. Future hardening: verify the connection (e.g. certificate CN/SAN)
# before trusting, rather than trusting on domain string alone.
#
# Registrable domains (no protocol, no path). Subdomains match automatically:
# "mail.google.com" is trusted because "google.com" is on the list. A more
# specific entry (e.g. "developer.mozilla.org") also matches directly, in
# addition to its registrable domain ("mozilla.org") if that were listed too.
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

    # Well-known reference/security/productivity tools whose deep-linked
    # pages (long paths, embedded hashes/digits, dataset/tool-name slugs)
    # get misread as phishing-shaped by the URL-structure-only model, even
    # though the sites themselves are unambiguously legitimate.
    "quillbot.com", "virustotal.com", "archive.ics.uci.edu",
    "grammarly.com", "turnitin.com", "scholar.google.com",
    "researchgate.net", "sciencedirect.com", "ieee.org", "springer.com",
    "kaggle.com", "colab.research.google.com",
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


def _domain_candidates(host: str) -> list:
    """
    All suffixes of host from the full host down to (and including) its
    registrable domain, most specific first, e.g.:
        "developer.mozilla.org" -> ["developer.mozilla.org", "mozilla.org"]
        "mail.google.com"       -> ["mail.google.com", "google.com"]

    Lets a listed entry match whether it's the registrable domain (the
    common case -- subdomains match through it) or a specific subdomain
    entry (e.g. "developer.mozilla.org"), without ever matching on a bare
    TLD/suffix below the registrable domain.
    """
    host = (host or "").lower().strip().split(":")[0]
    if not host:
        return []
    parts = host.split(".")
    if len(parts) < 2:
        return [host]

    registrable = _registrable_domain(host)
    reg_len = len(registrable.split("."))
    return [".".join(parts[i:]) for i in range(0, len(parts) - reg_len + 1)]


# Query parameters that services use to send the visitor on to another
# address (google.com/url?q=..., facebook.com/l.php?u=..., Outlook Safe
# Links ?url=...). On a trusted domain such a link opens the address in the
# parameter, so that address is what has to be checked.
_REDIRECT_PARAMS = {
    "q", "u", "url", "uri", "link", "target", "dest", "destination", "redir",
    "redirect", "redirect_uri", "redirect_url", "continue", "next", "goto",
    "return", "returnurl", "return_url", "returnto", "r",
}


def _with_scheme(url: str) -> str:
    raw = (url or "").strip()
    return raw if raw.lower().startswith(("http://", "https://")) else "http://" + raw


def redirect_destination(url: str) -> str:
    """The address on another website that a redirect parameter of the URL
    points to, or empty string if there is none."""
    parsed = urlparse(_with_scheme(url))
    own = _registrable_domain(parsed.hostname or "")
    for key, value in parse_qsl(parsed.query):
        value = value.strip()
        if key.lower() in _REDIRECT_PARAMS and value.lower().startswith(("http://", "https://", "//")):
            dest = "https:" + value if value.startswith("//") else value
            host = (urlparse(dest).hostname or "").lower()
            if host and _registrable_domain(host) != own:
                return dest
    return ""


def _listed_domain(url: str) -> str:
    """The allowlist entry the URL's host falls under, or empty string."""
    if not url:
        return ""
    try:
        raw = _with_scheme(url)
        # Never trust user-published content, even on a trusted company's
        # domain (e.g. sites.google.com, docs.google.com forms) - attackers
        # host phishing pages there precisely because of the trusted name.
        from .reputation import is_user_content_host
        if is_user_content_host(raw):
            return ""
        host = urlparse(raw).netloc
        for c in _domain_candidates(host):
            if c in TRUSTED_DOMAINS:
                return c
        return ""
    except Exception:
        return ""


def matched_domain(url: str) -> str:
    """Return the trusted domain that matched, or empty string if none. A
    redirect link to a website that is not trusted itself never matches."""
    domain = _listed_domain(url)
    if domain:
        dest = redirect_destination(url)
        if dest and not matched_domain(dest):
            return ""
    return domain


def is_trusted(url: str) -> bool:
    """
    Return True if the URL's host (or any of its parent domains, down to
    its registrable domain) is on the trusted allowlist and the URL does
    not redirect to an untrusted website. Handles URLs with or without a
    scheme.
    """
    return bool(matched_domain(url))


def unwrap_redirect(url: str, max_hops: int = 3) -> str:
    """The address that a redirect link on a trusted service opens (a
    Google search-result link, Outlook Safe Links, Facebook l.php), or the
    URL itself when it is not one. Only allowlisted services are unwrapped:
    on any other website the parameter may be decoration that the page
    ignores, so that website is what gets checked."""
    from .schemas import _validate_url
    for _ in range(max_hops):
        dest = redirect_destination(url) if _listed_domain(url) else ""
        if not dest:
            break
        try:
            url = _validate_url(dest)
        except ValueError:
            break
    return url
