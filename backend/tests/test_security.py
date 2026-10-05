"""Security tests: SQL injection, JWT tampering/expiry, password storage, IDOR."""
import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.auth import ALGORITHM, SECRET_KEY, verify_password
from app.models import User

from conftest import STRONG_PASSWORD, auth, login, register

S = "Security"
SQLI = [
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "' UNION SELECT id, email, password_hash FROM users--",
]


def _users_intact(db, expected):
    db.expire_all()
    return db.query(User).count() == expected


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("payload", SQLI)
def test_sqli_login_email(client, tc, db, payload):
    tc("SQL injection", S, "SQL injection in the login email field", payload,
       "422 rejected as invalid email; no login; users table intact")
    register(client, "victim@test.com")
    r = login(client, payload, "anything")
    tc.actual(f"{r.status_code}; users intact={_users_intact(db, 1)}")
    assert r.status_code == 422 and "access_token" not in r.text
    assert _users_intact(db, 1)


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_login_password(client, tc, db, payload):
    tc("SQL injection", S, "SQL injection in the login password field", payload,
       "401; no token; users table intact")
    register(client, "victim@test.com")
    r = login(client, "victim@test.com", payload)
    tc.actual(f"{r.status_code}; users intact={_users_intact(db, 1)}")
    assert r.status_code == 401 and "access_token" not in r.text
    assert _users_intact(db, 1)


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_register_name(client, tc, db, payload):
    tc("SQL injection", S, "SQL injection in the register full-name field", payload,
       "201; name stored as plain text; users table intact")
    register(client, "first@test.com")
    r = register(client, "attacker@test.com", name=payload)
    tc.actual(f"{r.status_code}; stored name equal to input={r.json()['user']['full_name'] == payload}; "
              f"users intact={_users_intact(db, 2)}")
    assert r.status_code == 201 and r.json()["user"]["full_name"] == payload
    assert _users_intact(db, 2)


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_register_email(client, tc, payload):
    tc("SQL injection", S, "SQL injection in the register email field", payload, "422 invalid email")
    r = register(client, payload)
    tc.actual(str(r.status_code))
    assert r.status_code == 422


@pytest.mark.parametrize("payload", ["1'%20OR%20'1'='1", "1';DROP%20TABLE%20users;--",
                                     "1'%20UNION%20SELECT%20password_hash%20FROM%20users--"])
def test_sqli_scan_url(client, tc, db, user_token, payload):
    url = f"http://example-shop.com/item?id={payload}"
    tc("SQL injection", S, "SQL injection inside a scanned URL's query string", url,
       "200 scanned normally; URL stored literally; users table intact")
    r = client.post("/api/scan", json={"url": url}, headers=auth(user_token))
    hist = client.get("/api/detections", headers=auth(user_token)).json()
    tc.actual(f"{r.status_code}; prediction={r.json().get('prediction')}; "
              f"stored literally={hist['items'][0]['url'] == url}; users intact={_users_intact(db, 2)}")
    assert r.status_code == 200 and hist["items"][0]["url"] == url
    assert _users_intact(db, 2)


@pytest.mark.parametrize("param", ["q", "result", "risk", "attack_type", "source", "date_from"])
@pytest.mark.parametrize("payload", SQLI)
def test_sqli_detection_filters(client, tc, db, user_token, admin_token, param, payload):
    tc("SQL injection", S, f"SQL injection in the history filter '{param}'", f"{param}={payload}",
       "No other users' rows and no password hashes returned; users table intact")
    client.post("/api/scan", json={"url": "https://numpy.org"}, headers=auth(admin_token))
    client.post("/api/scan", json={"url": "https://scikit-learn.org"}, headers=auth(user_token))
    r = client.get("/api/detections", params={param: payload}, headers=auth(user_token))
    body = r.json()
    leaked = "numpy.org" in r.text or "$2b$" in r.text or "admin@test.com" in r.text
    tc.actual(f"{r.status_code}; rows={body.get('total', body.get('detail'))}; leaked data={leaked}; "
              f"users intact={_users_intact(db, 2)}")
    # date filters reject non-dates with 400; text filters run as bound parameters
    assert r.status_code == (400 if param == "date_from" else 200) and not leaked
    assert body.get("total", 0) <= 1
    assert _users_intact(db, 2)


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_admin_detection_search(client, tc, db, admin_token, payload):
    tc("SQL injection", S, "SQL injection in the admin Detection Logs search", f"q={payload}",
       "200 with 0 matches; no password hashes; users table intact")
    client.post("/api/scan", json={"url": "https://numpy.org"}, headers=auth(admin_token))
    r = client.get("/api/admin/detections", params={"q": payload}, headers=auth(admin_token))
    tc.actual(f"{r.status_code}; rows={r.json().get('total')}; hash leaked={'$2b$' in r.text}")
    assert r.status_code == 200 and r.json()["total"] == 0 and "$2b$" not in r.text
    assert _users_intact(db, 1)


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_jwt_tampered_role(client, tc, user_token):
    tc("JWT", S, "Edit the token payload to role=admin, keep the old signature",
       "user token with modified payload", "401 Invalid credentials")
    header, _, sig = user_token.split(".")
    payload = jwt.decode(user_token, options={"verify_signature": False})
    payload["role"] = "admin"
    payload["sub"] = "1"
    forged = f"{header}.{_b64(payload)}.{sig}"
    r = client.get("/api/admin/users", headers=auth(forged))
    tc.actual(f"{r.status_code}; {r.json().get('detail')}")
    assert r.status_code == 401


def test_jwt_wrong_secret(client, tc, user_token):
    tc("JWT", S, "Token signed with a different secret key", "HS256 token, wrong key",
       "401 Invalid credentials")
    forged = jwt.encode({"sub": "1", "role": "admin",
                         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                        "attacker-secret-key-that-is-long-enough!", algorithm="HS256")
    r = client.get("/api/auth/me", headers=auth(forged))
    tc.actual(f"{r.status_code}; {r.json().get('detail')}")
    assert r.status_code == 401


def test_jwt_alg_none(client, tc, user_token):
    tc("JWT", S, "Unsigned token using alg=none", "alg none token claiming admin", "401")
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '1', 'role': 'admin'})}."
    r = client.get("/api/auth/me", headers=auth(forged))
    tc.actual(str(r.status_code))
    assert r.status_code == 401


def test_jwt_expired(client, tc, user_token):
    tc("JWT", S, "Correctly signed but expired token", "exp = 1 minute ago",
       "401 Session expired")
    expired = jwt.encode({"sub": "2", "role": "user", "email": "user@test.com",
                          "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
                         SECRET_KEY, algorithm=ALGORITHM)
    r = client.get("/api/auth/me", headers=auth(expired))
    tc.actual(f"{r.status_code}; {r.json().get('detail')}")
    assert r.status_code == 401 and "expired" in r.json()["detail"].lower()


def test_jwt_deactivated_user_token(client, tc, db, user_token):
    tc("JWT", S, "Valid token of a user who was deactivated afterwards", "deactivate, reuse token",
       "401 Account no longer active")
    db.query(User).filter(User.email == "user@test.com").update({User.is_active: False})
    db.commit()
    r = client.get("/api/auth/me", headers=auth(user_token))
    tc.actual(f"{r.status_code}; {r.json().get('detail')}")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Password storage and object-level access
# ---------------------------------------------------------------------------
def test_password_stored_as_bcrypt(client, tc, db):
    tc("Password storage", S, "Password is stored as a salted bcrypt hash, never plain text",
       STRONG_PASSWORD, "hash starts with $2b$, differs from the password, verifies")
    register(client, "a@test.com")
    register(client, "b@test.com")
    a, b = (db.query(User).filter(User.email == e).one().password_hash
            for e in ("a@test.com", "b@test.com"))
    tc.actual(f"prefix={a[:4]}; plain stored={a == STRONG_PASSWORD}; "
              f"same password -> different hashes={a != b}; verifies={verify_password(STRONG_PASSWORD, a)}")
    assert a.startswith("$2b$") and a != STRONG_PASSWORD and a != b
    assert verify_password(STRONG_PASSWORD, a)


def test_api_never_returns_password_hash(client, tc, admin_token):
    tc("Password storage", S, "Login, /me and admin user list never return the password hash",
       "admin token", "no '$2b$' or 'password_hash' in responses")
    texts = [login(client, "admin@test.com").text,
             client.get("/api/auth/me", headers=auth(admin_token)).text,
             client.get("/api/admin/users", headers=auth(admin_token)).text]
    leaked = any("$2b$" in t or "password_hash" in t for t in texts)
    tc.actual(f"leaked={leaked}")
    assert not leaked


def test_cannot_unblock_other_users_block(client, tc, admin_token, user_token):
    tc("Access control", S, "A user cannot delete another user's blocked-URL entry (IDOR)",
       "user DELETEs admin's block id", "404; admin's block still present")
    client.post("/api/extension/user-blocks", json={"url": "http://x-bad.xyz"}, headers=auth(admin_token))
    block_id = client.get("/api/my-blocked-urls", headers=auth(admin_token)).json()[0]["id"]
    r = client.delete(f"/api/my-blocked-urls/{block_id}", headers=auth(user_token))
    still = client.get("/api/my-blocked-urls", headers=auth(admin_token)).json()
    tc.actual(f"{r.status_code}; admin block still present={len(still) == 1}")
    assert r.status_code == 404 and len(still) == 1
