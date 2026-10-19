"""
The full check of one URL, shared by the website scanner (/api/scan), the
explanation (/api/explain) and the Chrome extension (/api/extension/scan):

  1. redirect unwrapping - a Google / Outlook Safe Links redirect on a
     trusted service is checked by the address it opens (allowlist.py)
  2. trusted allowlist
  3. URL model + post-model rules (ml_state.classify_vec)
  4. live page check (page_check.py) for a Suspicious result:
       - a short link is followed and the address it opens is checked
         from step 2 again (the result is for that address);
       - a risk on the page (a password form sending to another website,
         a password asked for in another company's name, a form service
         collecting passwords, a redirect to a phishing address) raises
         Suspicious to Phishing (escalated_by "page_check");
       - on a well-established domain (reputation.py), a page that loads,
         names only its own website and has no risk lowers Suspicious to
         Legitimate (legit_reason "page_check").
     Phishing results are never lowered: for them the page check only adds
     findings to the explanation.
"""
from urllib.parse import urlparse

from . import page_check
from .allowlist import matched_domain, unwrap_redirect
from .features import extract_features, feature_vector
from .ml_state import classify_vec
from .reputation import _extract_icann
from .schemas import _validate_url

_SIGN_IN_HOSTS = ("login.", "signin.", "accounts.", "account.", "auth.", "sso.", "idp.")


def _domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return _extract_icann(host).top_domain_under_public_suffix or host


def _destination_signals(page: dict) -> list:
    """Extra findings for a page that ended on another website."""
    final = page["final_url"]
    host = (urlparse(final).hostname or "").lower()
    if matched_domain(final):
        return []
    try:
        dest = _validate_url(final)
    except ValueError:
        return []
    verdict = classify_vec(feature_vector(dest), extract_features(dest), dest)
    if verdict["prediction"] == "phishing":
        return [{"kind": "risk", "code": "redirects_to_phishing",
                 "text": f"Opening the link sends visitors on to {_domain(final)}, which the URL check "
                         "flags as phishing."}]
    if page["asks_secret"] or host.startswith(_SIGN_IN_HOSTS):
        return [{"kind": "info", "code": "sign_in_wall",
                 "text": f"The link leads to a sign-in page on {_domain(final)}, so the content behind it "
                         "could not be checked."}]
    return []


def apply_page_check(verdict: dict, page: dict) -> None:
    """Change a Suspicious verdict by the page findings (in place)."""
    verdict["page_check"] = page
    if verdict["prediction"] != "uncertain":
        return
    rep = verdict.get("reputation") or {}
    verdict["url_reason"] = verdict["uncertain_reason"]
    if any(s["kind"] == "risk" for s in page["signals"]):
        verdict.update(prediction="phishing", risk="High", uncertain_reason=None,
                       legit_reason=None, escalated_by="page_check")
    elif (page["reachable"] and page["self_named"] and not page["left_site"]
          and verdict["uncertain_reason"] != "short_link"
          and rep.get("reputable") and not rep.get("abused")):
        verdict.update(prediction="legitimate", risk="Low", uncertain_reason=None,
                       legit_reason="page_check")


def evaluate(url: str, page_for=("uncertain",)) -> dict:
    """Run the whole check. page_for: the verdicts the page check runs for
    (the explanation also asks for "phishing", to show its findings).

    {"url": as entered, "checked": the address the result is for,
     "checked_url": that address when it differs from the input, else None,
     "trusted": matched allowlist domain or "", "vec", "features",
     "verdict": classify_vec result (None when trusted)}"""
    checked = unwrap_redirect(url)
    followed = False
    while True:
        out = {"url": url, "checked": checked, "checked_url": checked if checked != url else None,
               "trusted": matched_domain(checked), "vec": None, "features": None, "verdict": None}
        if out["trusted"]:
            return out
        vec, features = feature_vector(checked), extract_features(checked)
        verdict = classify_vec(vec, features, checked)
        verdict["page_check"] = None
        out.update(vec=vec, features=features, verdict=verdict)
        if not page_check.enabled() or verdict["prediction"] not in page_for:
            return out
        page = page_check.check(checked)
        # A short link: judge the address it opens instead.
        if verdict["uncertain_reason"] == "short_link" and page["left_site"] and not followed:
            try:
                checked = unwrap_redirect(_validate_url(page["final_url"]))
                followed = True
                continue
            except ValueError:
                pass
        if page["left_site"] and verdict["uncertain_reason"] != "short_link":
            extra = _destination_signals(page)
            if extra:
                page = dict(page, signals=page["signals"] + extra)
        apply_page_check(verdict, page)
        return out
