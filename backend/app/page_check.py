"""
Live page check (runs AFTER the URL model and its rules).

Why: the model only reads the URL text, so some genuine links look like
phishing (a login page on a university site) and some phishing looks
harmless. The page itself shows what the URL cannot: where a link really
leads and whether the page asks for a password on behalf of a company
that does not own the website.

What it does, for a URL the other layers leave Suspicious (and, for the
explanation only, Phishing):
  1. Fetches the page the way a browser opens it, following up to
     MAX_HOPS redirects (HTTP 3xx, <meta http-equiv="refresh"> and the
     simple JavaScript redirects used by redirect pages).
  2. Reads the final HTML for a few signals that can be explained in one
     sentence each (analyse()).
It never runs JavaScript, never submits a form and never sends cookies.

Safety: the server opens addresses chosen by users, so every hop is
resolved first and refused when it points at a private, loopback or
otherwise internal address (no access to the local network through this
feature), only ports 80/443/8080/8443 are allowed, the whole fetch is
limited to FETCH_DEADLINE seconds and MAX_BYTES of HTML.

Known limits: a phishing kit can show automated visitors a harmless page
(cloaking); pages behind a sign-in (SharePoint, Google Drive) show only the
sign-in page; pages that build everything with JavaScript expose little
HTML; phishing pages are often taken down within hours.

Set PHISHGUARD_PAGE_CHECK=0 to switch the check off (the test suite does).
"""
import ipaddress
import os
import re
import socket
import threading
import time
from collections import OrderedDict
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .brands import _WORD_BRANDS, FEED_BRANDS, MODEL_BRANDS, MY_BRANDS, _is_official, brand_display
from .reputation import _extract_icann, domain_reputation

FETCH_DEADLINE = 6.0          # seconds for the whole chain of hops
CONNECT_TIMEOUT = 3.0
MAX_HOPS = 5
MAX_BYTES = 1_000_000
ALLOWED_PORTS = {80, 443, 8080, 8443}
CACHE_SECONDS = 600
CACHE_SIZE = 512
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/129.0 Safari/537.36")


def enabled() -> bool:
    return os.environ.get("PHISHGUARD_PAGE_CHECK", "1") != "0"


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------
class BlockedAddress(Exception):
    """The address resolves to the local network or uses another port."""


def _guard(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedAddress(f"unsupported scheme {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise BlockedAddress("local host name")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise BlockedAddress(f"port {port} is not allowed")
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ConnectionError(f"the domain name does not resolve ({exc.strerror or exc})")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified):
            raise BlockedAddress("the address points to a private or internal network")


_JS_REDIRECT = re.compile(
    r"""(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*['"](https?://[^'"\s]+)['"]""",
    re.I)


def _refresh_target(url: str, content: str) -> str:
    """Target of a Refresh header or meta tag ("0; URL=https://..."), or
    empty string when there is none or the delay is over 10 seconds."""
    parts = re.split(r"[;,]", content or "", maxsplit=1)
    if len(parts) < 2:
        return ""
    try:
        if float(parts[0].strip() or 0) > 10:
            return ""
    except ValueError:
        return ""
    target = re.sub(r"^\s*url\s*=\s*", "", parts[1], flags=re.I).strip().strip("'\"").strip()
    return urljoin(url, target) if target else ""


def _next_hop_in_html(url: str, html: str) -> str:
    """Target of a meta-refresh or of a JavaScript redirect on a small
    redirect page, or empty string."""
    soup = BeautifulSoup(html[:200_000], "lxml")
    for meta in soup.find_all("meta"):
        # A refresh inside <noscript> only applies when scripts are off.
        if (meta.get("http-equiv") or "").lower() == "refresh" and not meta.find_parent("noscript"):
            target = _refresh_target(url, meta.get("content") or "")
            if target:
                return target
    # Only a page with almost no content of its own is a redirect page; a
    # normal page may mention location.href in a script for other reasons.
    if len(soup.get_text(" ", strip=True)) < 300:
        match = _JS_REDIRECT.search(html)
        if match:
            return match.group(1)
    return ""


def fetch(url: str) -> dict:
    """Open the URL like a browser would, without running scripts.

    {"chain": [every address visited], "final_url", "status": int|None,
     "content_type", "html": str|None, "error": str|None,
     "certificate_error": bool}"""
    out = {"chain": [url], "final_url": url, "status": None, "content_type": "",
           "html": None, "error": None, "certificate_error": False}
    deadline = time.monotonic() + FETCH_DEADLINE
    verify = True
    current = url
    try:
        for _ in range(MAX_HOPS + 1):
            _guard(current)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise httpx.TimeoutException("the page took too long to respond")
            timeout = httpx.Timeout(min(remaining, FETCH_DEADLINE), connect=min(remaining, CONNECT_TIMEOUT))
            try:
                with httpx.Client(follow_redirects=False, verify=verify, timeout=timeout,
                                  headers={"User-Agent": USER_AGENT,
                                           "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                                           "Accept-Language": "en-US,en;q=0.9"}) as client:
                    with client.stream("GET", current) as resp:
                        out["status"] = resp.status_code
                        out["final_url"] = current
                        location = resp.headers.get("location")
                        if resp.is_redirect and location:
                            current = urljoin(current, location)
                            out["chain"].append(current)
                            continue
                        refresh = resp.headers.get("refresh")
                        out["content_type"] = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                        body = b""
                        if "html" in out["content_type"] or not out["content_type"]:
                            for chunk in resp.iter_bytes():
                                body += chunk
                                if len(body) >= MAX_BYTES or time.monotonic() > deadline:
                                    break
                        html = body[:MAX_BYTES].decode(resp.encoding or "utf-8", errors="replace") if body else ""
            except httpx.ConnectError as exc:
                if verify and "CERTIFICATE" in str(exc).upper():
                    # Read the page anyway (nothing is sent to it) and
                    # report the invalid certificate as a finding.
                    verify = False
                    out["certificate_error"] = True
                    continue
                raise
            target = _refresh_target(current, refresh) if refresh else ""
            if not target and html and resp.status_code < 400:
                target = _next_hop_in_html(current, html)
            if target and target != current:
                current = target
                out["chain"].append(current)
                continue
            out["html"] = html
            return out
        out["error"] = f"more than {MAX_HOPS} redirects"
    except BlockedAddress as exc:
        out["error"] = f"not opened: {exc}"
    except ConnectionError as exc:
        out["error"] = str(exc)
    except httpx.InvalidURL:
        out["error"] = "the address could not be opened by the checker (its domain name is not valid)"
    except httpx.TimeoutException:
        out["error"] = "the page took too long to respond"
    except httpx.HTTPError as exc:
        out["error"] = f"the page could not be opened ({type(exc).__name__})"
    return out


# ---------------------------------------------------------------------------
# Brands named on a page
# ---------------------------------------------------------------------------
# Companies that sign people in on several domains of their own.
_FAMILIES = {
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
                  "outlook.com", "sharepoint.com", "onedrive.com", "hotmail.com", "msn.com",
                  "azure.com", "bing.com", "skype.com", "xbox.com", "microsoft365.com", "aka.ms"),
    "google": ("google.com", "gmail.com", "youtube.com", "googleusercontent.com", "blogger.com"),
    "apple": ("apple.com", "icloud.com", "me.com"),
    "facebook": ("facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com", "messenger.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.sg", "amazon.co.jp", "aws.amazon.com"),
    "yahoo": ("yahoo.com", "yahoo.co.jp", "aol.com"),
}
_FAMILY_OF = {
    "outlook": "microsoft", "office365": "microsoft", "onedrive": "microsoft", "sharepoint": "microsoft",
    "hotmail": "microsoft", "microsoftonline": "microsoft", "gmail": "google", "icloud": "apple",
    "instagram": "facebook", "whatsapp": "facebook", "fb": "facebook",
}
# Names searched for on a page: the phishing-feed brands, the model's
# brand list, the Malaysian brands, and the product names phishing pages
# put in their titles.
_PAGE_BRANDS = sorted(
    {b for b in FEED_BRANDS}
    | {a for meta in MODEL_BRANDS.values() for a in meta["aliases"] if len(a) >= 3}
    | set(MY_BRANDS)
    | {"google", "gmail", "onedrive", "sharepoint", "office365", "dropbox", "webex", "zoom"},
    key=len, reverse=True)
_SHORT_NAME = 5   # shorter names must stand alone as a word (dhl, cimb, apple)


def _compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


def _has_word(word: str, low_text: str) -> bool:
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", low_text))


def brands_named(text: str) -> set:
    """Brand names that appear in the text. Long names also count when
    written with spaces ("Wells Fargo"); short names and names that are
    ordinary words (outlook, ledger) only as a separate word."""
    low = (text or "").lower()
    compact = _compact(text)
    found = set()
    for name in _PAGE_BRANDS:
        if len(name) >= _SHORT_NAME and name not in _WORD_BRANDS:
            if name in compact:
                found.add(name)
        elif _has_word(name, low):
            found.add(name)
    if "office 365" in low or "microsoft 365" in low:
        found.add("office365")
    return found


def owns_brand(brand: str, domain: str) -> bool:
    """True when the registered domain belongs to the brand's company."""
    family = _FAMILY_OF.get(brand, brand)
    if any(domain == d or domain.endswith("." + d) for d in _FAMILIES.get(family, ())):
        return True
    if brand in MY_BRANDS and _is_official(domain, MY_BRANDS[brand][2]):
        return True
    for meta in MODEL_BRANDS.values():
        if brand in meta["aliases"] and any(domain == d or domain.endswith("." + d)
                                            for d in meta["official_domains"]):
            return True
    label = domain.split(".")[0]
    return brand in label or family in label


# ---------------------------------------------------------------------------
# Page signals
# ---------------------------------------------------------------------------
# Where phishing kits send what the victim types, instead of to a server of
# their own: chat bots, webhooks and form-collection services.
_COLLECTORS = ("api.telegram.org", "discord.com/api/webhooks", "discordapp.com/api/webhooks",
               "webhook.site", "formspree.io", "formsubmit.co", "getform.io", "submit-form.com",
               "script.google.com/macros", "hooks.slack.com", "pipedream.net", "ntfy.sh")
_SECRET_FIELD = re.compile(r"pass(?:word|wd|code)?(?![a-z])|pwd|kata\s*laluan|(?<![a-z])(?:otp|tac|pin|cvv|cvc)(?![a-z])"
                           r"|card.?number|cc.?num", re.I)
_SECRET_QUESTION = re.compile(r"(?<![a-z])(password|kata\s*laluan|passcode|one[- ]time\s*pin|otp|tac\s*code)(?![a-z])", re.I)
_FORM_SERVICES = ("docs.google.com/forms", "forms.office.com", "forms.microsoft.com", "jotform.com",
                  "typeform.com", "forms.app", "hsforms.com", "surveymonkey.com", "123formbuilder.com")


def _reg(host: str) -> str:
    return _extract_icann(host or "").top_domain_under_public_suffix or (host or "")


def _secret_inputs(scope) -> list:
    found = []
    for field in scope.find_all("input"):
        kind = (field.get("type") or "text").lower()
        if kind in ("hidden", "submit", "button", "checkbox", "radio", "image"):
            continue
        attrs = " ".join(str(field.get(a) or "") for a in ("name", "id", "placeholder", "aria-label", "autocomplete"))
        if kind == "password" or _SECRET_FIELD.search(attrs):
            found.append(field)
    return found


def facts_from_html(url: str, html: str) -> dict:
    """The parts of a page that judge() reads, taken from its HTML."""
    soup = BeautifulSoup(html or "", "lxml")
    meta = {(m.get("property") or m.get("name") or "").lower(): (m.get("content") or "")
            for m in soup.find_all("meta")}
    text = soup.get_text(" ", strip=True)
    secret_forms = [f for f in soup.find_all("form") if _secret_inputs(f)]
    low_html = (html or "").lower()
    return {
        "title": (soup.title.get_text(" ", strip=True) if soup.title else "")[:200],
        "site_name": meta.get("og:site_name", ""),
        "og_title": meta.get("og:title", ""),
        "app_name": meta.get("application-name", ""),
        "copyright": " ".join(m.group(0) for m in re.finditer(
            r"(?:\u00a9|&copy;|copyright)[^.|\n]{0,60}", text, re.I))[:300],
        "headings": " ".join(h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2"])[:4]),
        "logos": " ".join(f"{img.get('alt') or ''} {os.path.basename(urlparse(img.get('src') or '').path)}"
                          for img in soup.find_all("img")[:40]),
        "form_text": " ".join(f.get_text(" ", strip=True)[:500] for f in secret_forms),
        "form_actions": [(f.get("action") or "").strip() for f in secret_forms],
        "loose_secret": not secret_forms and bool(_secret_inputs(soup)),
        "collector": next((c for c in _COLLECTORS if c in low_html), ""),
        "has_form": "<form" in low_html,
        "text": text[:20_000],
    }


def judge(url: str, facts: dict) -> dict:
    """Signals from a page's facts. Each signal is {"kind": "risk" | "safe" |
    "info", "code", "text"}.

    The page's main identity is its title, site name and copyright line.
    "self_named" is True when that identity names this website (its own name
    or one of its owner's brands) and no other company. Logos, headings and
    form text count only for a page that does not name itself: a real page
    shows payment and "Sign in with Google" logos next to its own name."""
    host = (urlparse(url).hostname or "").lower()
    domain = _reg(host)
    own = domain.split(".")[0]
    signals = []
    title = facts.get("title", "")
    actions = facts.get("form_actions") or []
    asks_secret = bool(actions) or bool(facts.get("loose_secret"))

    main = " ".join([title, facts.get("site_name", ""), facts.get("og_title", ""),
                     facts.get("app_name", ""), facts.get("copyright", "")])
    secondary = " ".join([facts.get("headings", ""), facts.get("logos", ""), facts.get("form_text", "")])
    main_brands, other_brands = brands_named(main), brands_named(secondary)
    named = main_brands | other_brands
    foreign_main = sorted(b for b in main_brands if not owns_brand(b, domain))
    own_named = (any(owns_brand(b, domain) for b in main_brands)
                 or (len(own) >= 3 and _has_word(own, main.lower()))
                 or (len(own) >= 6 and own in _compact(main)))
    self_named = own_named and not foreign_main
    foreign = foreign_main or ([] if own_named else sorted(b for b in other_brands if not owns_brand(b, domain)))

    # 1. A password form whose data goes to another website.
    shared_sign_in = ""
    for action in actions:
        target = urljoin(url, action) if action else url
        t_host = (urlparse(target).hostname or "").lower()
        if action.lower().startswith("mailto:"):
            signals.append({"kind": "risk", "code": "form_to_email",
                            "text": "The page's password form sends what you type by e-mail, which no genuine sign-in page does."})
            break
        # Sign-in shared between a company's own well-established domains
        # (instructure.com -> canvas.net) is normal; sending to an unknown
        # or shared-hosting server is what a phishing kit does.
        target_rep = domain_reputation(target) if t_host and _reg(t_host) != domain else None
        if target_rep and not (target_rep["reputable"] and not target_rep["abused"]):
            signals.append({"kind": "risk", "code": "form_to_other_site",
                            "text": f"The page's password form sends what you type to another website ({_reg(t_host)})."})
            break
        if target_rep:
            shared_sign_in = _reg(t_host)
    # 2. Typed data sent to a chat bot or form-collection service.
    collector = facts.get("collector") or ""
    if collector and (asks_secret or facts.get("has_form")) and _reg(collector.split("/")[0]) != domain:
        signals.append({"kind": "risk", "code": "data_collector",
                        "text": f"The page contains code that sends form data to {collector.split('/')[0]}, "
                                "a way phishing kits collect stolen passwords."})
    # 3. A password requested in another company's name.
    if asks_secret and foreign:
        names = ", ".join(brand_display(b) for b in foreign[:2])
        signals.append({"kind": "risk", "code": "foreign_brand_login",
                        "text": f"The page asks for a password or card details and shows the name {names}, "
                                f"but {domain} does not belong to that company."})
    # 4. An online form that asks for a password. (The services' own
    # footer warning - "Never submit passwords through Google Forms." - is
    # removed first.)
    questions = re.sub(r"never (?:submit|give out|share)[^.]{0,80}", " ", facts.get("text", ""), flags=re.I)
    if any(s in url.lower() for s in _FORM_SERVICES) and _SECRET_QUESTION.search(questions):
        signals.append({"kind": "risk", "code": "form_asks_password",
                        "text": "This online form asks for a password or one-time code. Genuine organisations "
                                "never collect passwords through form services."})

    if not any(s["kind"] == "risk" for s in signals):
        if self_named:
            shown = title or facts.get("site_name", "")
            signals.append({"kind": "safe", "code": "self_named",
                            "text": f"The page identifies itself as {domain}"
                                    + (f" (title: \"{shown[:80]}\")" if shown else "")
                                    + " and shows no other company's name."})
        if asks_secret:
            signals.append({"kind": "safe", "code": "own_login",
                            "text": f"Its sign-in form sends the password to {shared_sign_in}, another "
                                    "well-established website, not to an unknown server." if shared_sign_in
                                    else "Its sign-in form sends the password to the same website."})
        else:
            signals.append({"kind": "safe", "code": "no_password",
                            "text": "The page does not ask for a password, PIN or card details."})
    return {"title": title, "asks_secret": asks_secret, "brands": named, "foreign_brands": foreign,
            "self_named": self_named, "signals": signals}


def analyse(url: str, html: str) -> dict:
    """judge() on a page's HTML."""
    return judge(url, facts_from_html(url, html))


# ---------------------------------------------------------------------------
# Cached check
# ---------------------------------------------------------------------------
_cache: "OrderedDict[str, tuple]" = OrderedDict()
_lock = threading.Lock()


def check(url: str) -> dict:
    """fetch() + analyse(), cached for CACHE_SECONDS so the scan and the
    explanation of the same URL agree (and the page is opened once).

    {"url", "final_url", "chain", "left_site": bool (final page is on
     another registered domain), "reachable": bool, "status", "error",
     "title", "self_named", "asks_secret", "signals": [...], "seconds"}"""
    now = time.monotonic()
    with _lock:
        hit = _cache.get(url)
        if hit and now - hit[0] < CACHE_SECONDS:
            _cache.move_to_end(url)
            return hit[1]
    started = time.monotonic()
    page = fetch(url)
    start_domain = _reg(urlparse(url).hostname or "")
    final_domain = _reg(urlparse(page["final_url"]).hostname or "")
    out = {"url": url, "final_url": page["final_url"], "chain": page["chain"],
           "left_site": final_domain != start_domain, "status": page["status"],
           "error": page["error"], "reachable": False, "title": "", "self_named": False,
           "asks_secret": False, "signals": []}
    if page["error"]:
        out["signals"].append({"kind": "info", "code": "unreachable",
                               "text": f"The page could not be checked: {page['error']}. Phishing pages are "
                                       "often taken down within hours, so this is not proof either way."})
    elif page["status"] and page["status"] >= 400:
        out["signals"].append({"kind": "info", "code": "http_error",
                               "text": f"The website answered with error {page['status']}, so the page content "
                                       "could not be checked (the page may have been removed)."})
    elif page["html"] is None or ("html" not in page["content_type"] and page["content_type"]):
        out["reachable"] = True
        out["signals"].append({"kind": "info", "code": "not_html",
                               "text": f"The link opens a file ({page['content_type'] or 'unknown type'}), "
                                       "not a web page, so no page content was checked."})
    else:
        out["reachable"] = True
        found = analyse(page["final_url"], page["html"])
        out.update(title=found["title"], self_named=found["self_named"], asks_secret=found["asks_secret"],
                   signals=found["signals"])
    if len(page["chain"]) > 1:
        hops = " -> ".join((urlparse(u).hostname or u) for u in page["chain"])
        out["signals"].insert(0, {"kind": "info", "code": "redirect",
                                  "text": f"Opening the link redirects: {hops}."})
    if page["certificate_error"]:
        out["signals"].append({"kind": "info", "code": "certificate",
                               "text": "The website's HTTPS certificate is not valid, which genuine sites rarely allow."})
    out["seconds"] = round(time.monotonic() - started, 2)
    with _lock:
        _cache[url] = (now, out)
        if out["final_url"] != url:
            # The page at the end of the chain, for when that address is
            # checked next (a short link's destination).
            _cache[out["final_url"]] = (now, dict(
                out, url=out["final_url"], chain=[out["final_url"]], left_site=False,
                signals=[s for s in out["signals"] if s["code"] != "redirect"]))
        while len(_cache) > CACHE_SIZE:
            _cache.popitem(last=False)
    return out
