"""
Domain age: how long ago a registered domain was first registered.

Why: most phishing domains are bought days or weeks before an attack and
abandoned soon after, while genuine websites - even small ones - keep their
domain for years. The URL text cannot show this, so the stage-2 model
(stage2.py) uses the age as one of its inputs.

Lookup order (no API key needed):
  1. RDAP, the registries' JSON service. The registry for each ending is
     found in IANA's bootstrap file (data.iana.org/rdap/dns.json), cached in
     outputs/rdap_bootstrap.json.
  2. WHOIS on port 43 for endings without RDAP (.my and many other country
     endings): IANA names the WHOIS server, whose text answer is searched
     for a creation date.
Results are cached per domain in memory and in outputs/domain_age_cache.json
(a registration date does not change); failures are cached for an hour.
"""
import json
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone

import httpx
from dateutil import parser as dateparser

_HERE = os.path.dirname(os.path.abspath(__file__))
_OUTPUTS = os.path.join(_HERE, "..", "..", "outputs")
_BOOTSTRAP = os.path.join(_OUTPUTS, "rdap_bootstrap.json")
_CACHE_FILE = os.path.join(_OUTPUTS, "domain_age_cache.json")
TIMEOUT = 4.0
_FAILED_RETRY_SECONDS = 3600

_lock = threading.Lock()
_cache = None          # domain -> {"registered": iso date | None, "source", "checked": epoch}
_rdap_bases = None     # tld -> RDAP base URL
_whois_servers = {}    # tld -> WHOIS server ("" when IANA names none)

_CREATED = re.compile(
    r"^\s*(?:creation date|created(?: on| date)?|domain registration date|registration date|"
    r"registration time|registered(?: on| date)?|record created|domain create date|"
    r"domain name commencement date|registered date)\s*\.*\s*[:\]]\s*(.+?)\s*$",
    re.I | re.M)


def _load_cache() -> dict:
    global _cache
    if _cache is None:
        try:
            with open(_CACHE_FILE, encoding="utf-8") as fh:
                _cache = json.load(fh)
        except (OSError, ValueError):
            _cache = {}
    return _cache


def _save_cache() -> None:
    try:
        os.makedirs(_OUTPUTS, exist_ok=True)
        tmp = _CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_cache, fh)
        os.replace(tmp, _CACHE_FILE)
    except OSError:
        pass


def _rdap_base(tld: str) -> str:
    global _rdap_bases
    if _rdap_bases is None:
        data = None
        if os.path.exists(_BOOTSTRAP) and time.time() - os.path.getmtime(_BOOTSTRAP) < 30 * 86400:
            with open(_BOOTSTRAP, encoding="utf-8") as fh:
                data = json.load(fh)
        else:
            try:
                data = httpx.get("https://data.iana.org/rdap/dns.json", timeout=10).json()
                os.makedirs(_OUTPUTS, exist_ok=True)
                with open(_BOOTSTRAP, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
            except Exception:
                data = {"services": []}
        _rdap_bases = {t: urls[0] for tlds, urls in data.get("services", []) for t in tlds}
    return _rdap_bases.get(tld, "")


def _parse_date(text: str):
    try:
        found = dateparser.parse(text.strip().split(" (")[0], fuzzy=True, dayfirst=False)
    except (ValueError, OverflowError):
        return None
    if found.tzinfo is None:
        found = found.replace(tzinfo=timezone.utc)
    if not 1985 <= found.year <= datetime.now(timezone.utc).year:
        return None
    return found


def _from_rdap(domain: str):
    base = _rdap_base(domain.rsplit(".", 1)[-1])
    if not base:
        return None, "no-rdap"
    resp = httpx.get(base.rstrip("/") + "/domain/" + domain, timeout=TIMEOUT, follow_redirects=True,
                     headers={"Accept": "application/rdap+json"})
    if resp.status_code == 404:
        return None, "rdap-not-found"
    resp.raise_for_status()
    for event in resp.json().get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            return _parse_date(event["eventDate"]), "rdap"
    return None, "rdap-no-date"


def _whois_query(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendall((query + "\r\n").encode("idna"))
        chunks = []
        while True:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 200_000:
                break
    return b"".join(chunks).decode("utf-8", errors="replace")


def _from_whois(domain: str):
    tld = domain.rsplit(".", 1)[-1]
    if tld not in _whois_servers:
        answer = _whois_query("whois.iana.org", tld)
        match = re.search(r"^whois:\s*(\S+)", answer, re.M)
        _whois_servers[tld] = match.group(1) if match else ""
    server = _whois_servers[tld]
    if not server:
        return None, "no-whois"
    text = _whois_query(server, domain)
    match = _CREATED.search(text)
    if match:
        return _parse_date(match.group(1)), "whois"
    return None, "whois-no-date"


def registered(domain: str):
    """Registration date (datetime, UTC) of a registered domain, or None."""
    domain = (domain or "").lower().strip(".")
    if not domain or "." not in domain:
        return None
    with _lock:
        hit = _load_cache().get(domain)
    if hit and (hit["registered"] or time.time() - hit["checked"] < _FAILED_RETRY_SECONDS):
        return datetime.fromisoformat(hit["registered"]) if hit["registered"] else None
    found, source = None, ""
    try:
        found, source = _from_rdap(domain)
    except Exception as exc:
        source = f"rdap-error:{type(exc).__name__}"
    if found is None and source in ("no-rdap", "rdap-no-date") or (found is None and source.startswith("rdap-error")):
        try:
            found, source = _from_whois(domain)
        except Exception as exc:
            source = f"whois-error:{type(exc).__name__}"
    with _lock:
        _load_cache()[domain] = {"registered": found.isoformat() if found else None,
                                 "source": source, "checked": time.time()}
        _save_cache()
    return found


def age_days(domain: str, when=None):
    """Days between registration and `when` (default now), or None."""
    found = registered(domain)
    if found is None:
        return None
    when = when or datetime.now(timezone.utc)
    return max((when - found).days, 0)
