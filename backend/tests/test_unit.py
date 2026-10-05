"""Unit tests: one feature at a time, through the API or the module directly."""
from datetime import datetime, timedelta

import pytest

from app.features import canonicalize_url, extract_features
from app.models import PasswordResetToken, User

from conftest import STRONG_PASSWORD, auth, login, register

U = "Unit"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("missing", ["full_name", "email", "password"])
def test_register_missing_field(client, tc, missing):
    body = {"full_name": "Ali", "email": "ali@test.com", "password": STRONG_PASSWORD}
    body.pop(missing)
    tc("Registration", U, f"Register without the mandatory field '{missing}'",
       f"body without {missing}", "422, account not created")
    r = client.post("/api/auth/register", json=body)
    tc.actual(f"{r.status_code}")
    assert r.status_code == 422


@pytest.mark.parametrize("password, rule", [
    ("Sh0rt!", "at least 8 characters"),
    ("lowercase1!", "an uppercase letter"),
    ("UPPERCASE1!", "a lowercase letter"),
    ("NoDigits!!", "a number"),
    ("NoSpecial12", "a special character"),
])
def test_register_weak_password(client, tc, password, rule):
    tc("Registration", U, f"Weak password rejected: missing {rule}",
       f"password={password}", f"422, message mentions '{rule}'")
    r = register(client, "weak@test.com", password)
    tc.actual(f"{r.status_code}; {r.text[:120]}")
    assert r.status_code == 422
    assert rule in r.text


def test_register_duplicate_email(client, tc):
    tc("Registration", U, "Register twice with the same email (case-insensitive)",
       "dup@test.com then DUP@test.com", "second request 409")
    register(client, "dup@test.com")
    r = register(client, "DUP@test.com")
    tc.actual(f"{r.status_code}; {r.json()['detail']}")
    assert r.status_code == 409


def test_register_valid(client, tc):
    tc("Registration", U, "Valid registration; first account becomes admin, second is user",
       "two valid accounts", "201 both; roles admin then user")
    r1 = register(client, "first@test.com")
    r2 = register(client, "second@test.com")
    tc.actual(f"{r1.status_code}/{r2.status_code}; roles "
              f"{r1.json()['user']['role']}/{r2.json()['user']['role']}")
    assert r1.status_code == r2.status_code == 201
    assert r1.json()["user"]["role"] == "admin"
    assert r2.json()["user"]["role"] == "user"


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
def test_login_correct_password(client, tc):
    tc("Login", U, "Login with correct credentials", "registered email + password",
       "200 with bearer token")
    register(client, "a@test.com")
    r = login(client, "a@test.com")
    tc.actual(f"{r.status_code}; token_type={r.json().get('token_type')}")
    assert r.status_code == 200 and r.json()["access_token"]


def test_login_wrong_password(client, tc):
    tc("Login", U, "Login with wrong password", "registered email + wrong password",
       "401 Invalid email or password")
    register(client, "a@test.com")
    r = login(client, "a@test.com", "Wr0ng!Pass")
    tc.actual(f"{r.status_code}; {r.json()['detail']}")
    assert r.status_code == 401


def test_login_unknown_email(client, tc):
    tc("Login", U, "Login with an unregistered email", "nobody@test.com",
       "401 with the same message as a wrong password")
    r = login(client, "nobody@test.com")
    tc.actual(f"{r.status_code}; {r.json()['detail']}")
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password"


def test_login_deactivated_user(client, tc, db):
    tc("Login", U, "Login to a deactivated account", "is_active = False",
       "403 account deactivated")
    register(client, "a@test.com")
    db.query(User).filter(User.email == "a@test.com").update({User.is_active: False})
    db.commit()
    r = login(client, "a@test.com")
    tc.actual(f"{r.status_code}; {r.json()['detail']}")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------
def _reset(client, email, code, new=STRONG_PASSWORD + "2"):
    return client.post("/api/auth/reset-password",
                       json={"email": email, "code": code, "new_password": new})


def test_reset_valid_code(client, tc, sent_codes):
    tc("Password reset", U, "Reset with the emailed 6-digit code", "correct code",
       "204, password changed")
    register(client, "a@test.com")
    client.post("/api/auth/forgot-password", json={"email": "a@test.com"})
    r = _reset(client, "a@test.com", sent_codes["a@test.com"])
    tc.actual(str(r.status_code))
    assert r.status_code == 204


def test_reset_expired_code(client, tc, sent_codes, db):
    tc("Password reset", U, "Reset with a code older than 10 minutes", "expired code",
       "400 invalid or expired")
    register(client, "a@test.com")
    client.post("/api/auth/forgot-password", json={"email": "a@test.com"})
    db.query(PasswordResetToken).update(
        {PasswordResetToken.expires_at: datetime.utcnow() - timedelta(minutes=1)})
    db.commit()
    r = _reset(client, "a@test.com", sent_codes["a@test.com"])
    tc.actual(f"{r.status_code}; {r.json()['detail']}")
    assert r.status_code == 400


def test_reset_five_wrong_attempts_burn_code(client, tc, sent_codes):
    tc("Password reset", U, "5 wrong codes burn the code; the right code then fails",
       "5 x wrong code, then correct code", "5th: 'Too many incorrect attempts'; then 400")
    register(client, "a@test.com")
    client.post("/api/auth/forgot-password", json={"email": "a@test.com"})
    good = sent_codes["a@test.com"]
    wrong = "000000" if good != "000000" else "111111"
    details = [_reset(client, "a@test.com", wrong).json()["detail"] for _ in range(5)]
    after = _reset(client, "a@test.com", good)
    tc.actual(f"5th: {details[-1]}; correct code afterwards: {after.status_code}")
    assert "Too many incorrect attempts" in details[-1]
    assert after.status_code == 400


def test_forgot_unknown_email_same_response(client, tc, sent_codes):
    tc("Password reset", U, "Forgot-password gives the same reply for unknown emails",
       "registered vs unregistered email", "identical 200 message; no code sent to unknown")
    register(client, "a@test.com")
    known = client.post("/api/auth/forgot-password", json={"email": "a@test.com"})
    unknown = client.post("/api/auth/forgot-password", json={"email": "ghost@test.com"})
    tc.actual(f"{known.status_code}/{unknown.status_code}; same body={known.json() == unknown.json()}")
    assert known.json() == unknown.json()
    assert "ghost@test.com" not in sent_codes


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("url, why", [
    ("", "empty"),
    ("http://exa mple.com", "contains spaces"),
    ("https://example.com/" + "a" * 2050, "longer than 2048 characters"),
    ("http://localhost:8000/login", "localhost"),
    ("http://192.168.1.10/admin", "private IP"),
    ("http://10.0.0.5", "private IP (10.x)"),
    ("asdfgh", "no dot in host"),
], ids=["empty", "spaces", "too-long", "localhost", "private-192", "private-10", "no-dot"])
def test_url_validation_rejects(client, tc, user_token, url, why):
    tc("URL validation", U, f"Scanner rejects URL: {why}", url[:60] + ("..." if len(url) > 60 else ""),
       "422, not scanned")
    r = client.post("/api/scan", json={"url": url}, headers=auth(user_token))
    tc.actual(str(r.status_code))
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# canonicalize_url / compute_features
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw, expected", [
    ("https://www.example.com/page/?utm_source=x&id=5#frag", "https://example.com/page?id=5"),
    ("example.com", "http://example.com"),
    ("https://shop.com/?fbclid=abc&gclid=1", "https://shop.com"),
])
def test_canonicalize_url(tc, raw, expected):
    tc("Feature extraction", U, "canonicalize_url strips www, tracking params, fragment, trailing /",
       raw, expected)
    out = canonicalize_url(raw)
    tc.actual(out)
    assert out == expected


@pytest.mark.parametrize("url, feature, expected", [
    ("https://example.com", "IsHTTPS", 1),
    ("http://example.com", "IsHTTPS", 0),
    ("http://45.33.32.156/paypal/login", "IsDomainIP", 1),
    ("https://a.b.example.com", "NoOfSubDomain", 2),
    ("https://www.example.com", "NoOfSubDomain", 0),
    ("http://paypal-login-verify.example.com/account/update", "NoOfSuspiciousWords", 3),
    ("http://paypal-login-verify.example.com/account/update", "HasBrandOutsideDomain", 1),
    ("https://www.paypal.com/signin", "HasBrandOutsideDomain", 0),
])
def test_compute_features(tc, url, feature, expected):
    tc("Feature extraction", U, f"compute_features gives the expected {feature}", url,
       f"{feature} = {expected}")
    value = extract_features(url)[feature]
    tc.actual(f"{feature} = {value}")
    assert value == expected


def test_feature_vector_has_22_features(tc):
    tc("Feature extraction", U, "Feature extractor returns exactly the 22 model features",
       "https://numpy.org", "22 keys")
    feats = extract_features("https://numpy.org")
    tc.actual(f"{len(feats)} keys")
    assert len(feats) == 22


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("url, prediction, extra", [
    ("https://github.com", "legitimate", {"trusted_domain": True, "model_used": "TrustedAllowlist"}),
    ("https://numpy.org", "legitimate", {"trusted_domain": False, "risk_level": "Low"}),
    ("http://paypa1-secure-login.win/verify.php?id=aGVsbG8=&acct=443", "phishing",
     {"risk_level": "High"}),
    ("https://web3.storage", "uncertain", {"risk_level": "Medium", "uncertain_reason": "borderline"}),
], ids=["trusted", "legitimate", "phishing", "suspicious"])
def test_classification(client, tc, user_token, url, prediction, extra):
    shown = {"legitimate": "Legitimate", "phishing": "Phishing", "uncertain": "Suspicious"}[prediction]
    if extra.get("trusted_domain"):
        shown = "Trusted Website"
    tc("Classification", U, f"Scanner verdict: {shown}", url,
       f"prediction={prediction}, " + ", ".join(f"{k}={v}" for k, v in extra.items()))
    r = client.post("/api/scan", json={"url": url}, headers=auth(user_token))
    body = r.json()
    tc.actual(f"prediction={body.get('prediction')}, p_phish={body.get('phishing_probability')}, "
              + ", ".join(f"{k}={body.get(k)}" for k in extra))
    assert r.status_code == 200
    assert body["prediction"] == prediction
    for k, v in extra.items():
        assert body[k] == v


def test_phishing_scan_has_attack_type(client, tc, user_token):
    tc("Classification", U, "Phishing verdict includes attack category and techniques",
       "http://45.33.32.156/paypal/login", "attack_type with category + 'IP Address Hosting'")
    r = client.post("/api/scan", json={"url": "http://45.33.32.156/paypal/login"},
                    headers=auth(user_token))
    at = r.json()["attack_type"]
    tc.actual(f"category={at['category']}; techniques={at['techniques']}")
    assert at["category"] and "IP Address Hosting" in at["techniques"]


# ---------------------------------------------------------------------------
# Report URL, user block / unblock
# ---------------------------------------------------------------------------
def test_report_url_pending(client, tc, user_token):
    tc("URL reporting", U, "Reporting a URL creates a pending report",
       "POST /api/report-url http://bad-login.xyz", "200, status = pending, in /api/my-reports")
    r = client.post("/api/report-url", json={"url": "http://bad-login.xyz"}, headers=auth(user_token))
    mine = client.get("/api/my-reports", headers=auth(user_token)).json()
    tc.actual(f"{r.status_code}; status={r.json().get('status')}; my-reports={len(mine)}")
    assert r.status_code == 200 and r.json()["status"] == "pending"
    assert len(mine) == 1


def test_report_url_duplicate(client, tc, user_token):
    tc("URL reporting", U, "The same URL cannot be reported twice", "same URL twice", "second 409")
    client.post("/api/report-url", json={"url": "http://bad-login.xyz"}, headers=auth(user_token))
    r = client.post("/api/report-url", json={"url": "http://bad-login.xyz"}, headers=auth(user_token))
    tc.actual(str(r.status_code))
    assert r.status_code == 409


def test_user_block_and_unblock(client, tc, user_token):
    tc("User block list", U, "Block a site from the extension, list it, then unblock it",
       "POST user-blocks, GET my-blocked-urls, DELETE", "saved; listed once; 204; list empty")
    h = auth(user_token)
    saved = client.post("/api/extension/user-blocks",
                        json={"url": "http://bad-login.xyz/a", "risk_level": "High"}, headers=h).json()
    again = client.post("/api/extension/user-blocks",
                        json={"url": "http://bad-login.xyz/b"}, headers=h).json()
    rows = client.get("/api/my-blocked-urls", headers=h).json()
    d = client.delete(f"/api/my-blocked-urls/{rows[0]['id']}", headers=h)
    after = client.get("/api/my-blocked-urls", headers=h).json()
    tc.actual(f"saved={saved['saved']}, duplicate host saved={again['saved']}, listed={len(rows)}, "
              f"delete={d.status_code}, after={len(after)}")
    assert saved["saved"] is True and again["saved"] is False
    assert len(rows) == 1 and rows[0]["hostname"] == "bad-login.xyz"
    assert d.status_code == 204 and after == []
