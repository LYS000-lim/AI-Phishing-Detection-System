"""Stage-2 model (stage2.py): the URL score combined with the domain's age.
Domain-age lookups are replaced by a stub - no test uses the network."""
from datetime import datetime, timedelta, timezone

import pytest

from app import domain_age, stage2
from app.features import extract_features, feature_vector
from app.ml_state import classify_vec

from conftest import auth

U, I = "Unit", "Integration"
# Stage 1 alone shows this live phishing URL (2026-10-16 feed) as Legitimate.
BORDERLINE = "https://docsewallet.com/Adobe_Installer.html"


@pytest.fixture
def domain_registered(monkeypatch):
    """Turn stage 2 on and make every domain registered `days` ago."""
    monkeypatch.setenv("PHISHGUARD_STAGE2", "1")
    ages = {"days": None}

    def fake(domain):
        if ages["days"] is None:
            return None
        return datetime.now(timezone.utc) - timedelta(days=ages["days"])

    monkeypatch.setattr(domain_age, "registered", fake)
    return ages


def verdict(url):
    return classify_vec(feature_vector(url), extract_features(url), url)


def test_stage2_age_moves_probability(tc, domain_registered):
    tc("Stage-2 model", U, "With the same URL score, a younger domain gives a higher stage-2 "
       "phishing probability", "stage-1 score 0.6; domain 5 days vs 20 years old",
       "p(5 days) > p(20 years)")
    domain_registered["days"] = 5
    young = stage2.score(0.6, "example-shop.com")
    domain_registered["days"] = 20 * 365
    old = stage2.score(0.6, "example-shop.com")
    tc.actual(f"{young['p']} vs {old['p']}")
    assert young["p"] > old["p"]
    assert young["age_days"] == 5


def test_stage2_raises_new_domain(tc, domain_registered):
    tc("Stage-2 model", U, "A URL the URL model alone shows as Legitimate is raised when its "
       "domain was registered days ago", BORDERLINE + " with a 5-day-old domain",
       "warning, reason new_domain")
    domain_registered["days"] = 5
    v = verdict(BORDERLINE)
    tc.actual(f"{v['prediction']} / {v['uncertain_reason'] or v['escalated_by']} / p2={v['stage2']['p']}")
    assert v["prediction"] in ("uncertain", "phishing")
    assert "new_domain" in (v["uncertain_reason"], v["escalated_by"])


def test_stage2_lowers_old_domain(tc, domain_registered):
    tc("Stage-2 model", U, "A high URL score on a domain held for decades is lowered by stage 2",
       "https://elearning.inti.edu.my/login/index.php with a 30-year-old domain",
       "legitimate, legit_reason established_domain")
    domain_registered["days"] = 30 * 365
    v = verdict("https://elearning.inti.edu.my/login/index.php")
    tc.actual(f"{v['prediction']} / {v['legit_reason']} / p1={v['p_phish']:.2f} p2={v['stage2']['p']}")
    assert v["prediction"] == "legitimate"
    assert v["legit_reason"] == "established_domain"


@pytest.mark.parametrize("url, why", [
    ("https://secure-login.weebly.com/", "shared hosting: the age would be the platform's"),
    ("https://bit.ly/abc123", "short link"),
    ("http://45.33.32.156/paypal/login", "IP address, no domain"),
])
def test_stage2_not_used(tc, domain_registered, url, why):
    tc("Stage-2 model", U, f"Stage 2 is not used for this kind of address ({why})", url, "stage2 is None")
    domain_registered["days"] = 3
    v = verdict(url)
    tc.actual(str(v["stage2"]))
    assert v["stage2"] is None


def test_stage2_unknown_age(tc, domain_registered):
    tc("Stage-2 model", U, "When the domain age cannot be found, the URL model decides alone",
       BORDERLINE + " with no age found", "stage2 None, same verdict as stage 1")
    domain_registered["days"] = None
    v = verdict(BORDERLINE)
    tc.actual(f"{v['prediction']} / stage2={v['stage2']}")
    assert v["stage2"] is None
    assert v["prediction"] == "legitimate"


def test_scan_and_explain_show_stage2(client, user_token, domain_registered, tc):
    tc("Stage-2 model", I, "Scan and explanation agree and the explanation names the domain's age",
       BORDERLINE + " with a 5-day-old domain", "same verdict; first reason mentions the registration")
    domain_registered["days"] = 5
    scan = client.post("/api/scan", json={"url": BORDERLINE}, headers=auth(user_token)).json()
    explain = client.post("/api/explain", json={"url": BORDERLINE}, headers=auth(user_token)).json()
    tc.actual(f"{scan['prediction']} / {explain['prediction']}; {explain['why_detected'][0][:80]}")
    assert scan["prediction"] == explain["prediction"] != "legitimate"
    assert scan["stage2"]["age_days"] == 5
    assert "was registered" in explain["why_detected"][0]


def test_stage2_keeps_warning_on_strong_lure(tc, domain_registered):
    tc("Stage-2 model", U, "An old domain does not clear an address with a strong lure (a hacked "
       "website): it stays Suspicious; login wording alone may be cleared",
       "30-year-old domain: wp-includes page naming PayPal vs a plain /login/index.php",
       "first Suspicious, second Legitimate")
    domain_registered["days"] = 30 * 365
    hacked = verdict("https://elearning.inti.edu.my/wp-includes/paypal/signin.php")
    login = verdict("https://elearning.inti.edu.my/login/index.php")
    tc.actual(f"{hacked['prediction']} {hacked['lures']}; {login['prediction']}")
    assert hacked["prediction"] == "uncertain"
    assert login["prediction"] == "legitimate"
