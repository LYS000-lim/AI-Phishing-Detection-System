"""Integration tests: multi-step flows across several endpoints."""
import pytest

from conftest import STRONG_PASSWORD, auth, login, register

I = "Integration"


def test_register_login_scan_history(client, tc, admin_token):
    tc("Scan workflow", I, "Register -> login -> scan -> scan appears in own history",
       "new user scans https://numpy.org", "history total 1 with the same URL and verdict")
    assert register(client, "flow@test.com").status_code == 201
    token = login(client, "flow@test.com").json()["access_token"]
    scan = client.post("/api/scan", json={"url": "https://numpy.org"}, headers=auth(token)).json()
    hist = client.get("/api/detections", headers=auth(token)).json()
    tc.actual(f"history total={hist['total']}; url={hist['items'][0]['url']}; "
              f"prediction={hist['items'][0]['prediction']}")
    assert hist["total"] == 1
    assert hist["items"][0]["url"] == "https://numpy.org"
    assert hist["items"][0]["prediction"] == scan["prediction"]


def test_history_is_private(client, tc, admin_token, user_token):
    tc("Scan workflow", I, "A user only sees their own scans", "admin scans, user lists history",
       "user history total 0")
    client.post("/api/scan", json={"url": "https://numpy.org"}, headers=auth(admin_token))
    hist = client.get("/api/detections", headers=auth(user_token)).json()
    tc.actual(f"user history total={hist['total']}")
    assert hist["total"] == 0


def test_extension_report_admin_approve_blacklist(client, tc, admin_token):
    tc("Report & blacklist", I,
       "Extension report -> admin approves -> check-blacklist blocks the domain",
       "POST /api/extension/report http://evil-login.xyz/verify", "pending, approved, blocked=True by admin")
    url = "http://evil-login.xyz/verify"
    before = client.get("/api/extension/check-blacklist", params={"url": url}).json()
    rep = client.post("/api/extension/report", json={"url": url, "attack_type": "Credential Theft"}).json()
    ok = client.post(f"/api/admin/extension-reports/{rep['id']}/approve", headers=auth(admin_token))
    after = client.get("/api/extension/check-blacklist",
                       params={"url": "https://evil-login.xyz/other-page"}).json()
    tc.actual(f"before blocked={before['blocked']}; report status={rep['status']}; "
              f"approve={ok.status_code}; after blocked={after['blocked']} by {after.get('blocked_by')}")
    assert before["blocked"] is False and rep["status"] == "pending"
    assert ok.status_code == 200
    assert after["blocked"] is True and after["blocked_by"] == "admin"
    assert after["attack_type"] == "Credential Theft"


def test_website_report_admin_approve_blacklist(client, tc, admin_token, user_token):
    tc("Report & blacklist", I, "Website report -> admin approves -> domain blacklisted",
       "POST /api/report-url http://fake-bank.top", "approved; check-blacklist blocked=True")
    rep = client.post("/api/report-url", json={"url": "http://fake-bank.top"},
                      headers=auth(user_token)).json()
    client.post(f"/api/admin/user-reports/{rep['id']}/approve", headers=auth(admin_token))
    after = client.get("/api/extension/check-blacklist", params={"url": "http://fake-bank.top"}).json()
    tc.actual(f"blocked={after['blocked']}; reported_via={after.get('reported_via')}")
    assert after["blocked"] is True and after["reported_via"] == "PhishGuard Website"


def test_user_block_list_cycle(client, tc, user_token):
    tc("User block list", I,
       "Extension user-block -> my-blocked-urls -> unblock -> check-blacklist clear",
       "block http://shady-shop.xyz while signed in", "blocked by user, then not blocked")
    h = auth(user_token)
    url = "http://shady-shop.xyz/cart"
    client.post("/api/extension/user-blocks", json={"url": url, "risk_level": "High"}, headers=h)
    listed = client.get("/api/my-blocked-urls", headers=h).json()
    blocked = client.get("/api/extension/check-blacklist", params={"url": url}, headers=h).json()
    anon = client.get("/api/extension/check-blacklist", params={"url": url}).json()
    client.delete(f"/api/my-blocked-urls/{listed[0]['id']}", headers=h)
    cleared = client.get("/api/extension/check-blacklist", params={"url": url}, headers=h).json()
    tc.actual(f"listed={len(listed)}; signed-in blocked={blocked['blocked']} ({blocked.get('blocked_by')}); "
              f"anonymous blocked={anon['blocked']}; after unblock={cleared['blocked']}")
    assert len(listed) == 1
    assert blocked["blocked"] is True and blocked["blocked_by"] == "user"
    assert anon["blocked"] is False
    assert cleared["blocked"] is False and cleared["user_checked"] is True


def test_forgot_reset_login(client, tc, sent_codes):
    tc("Password reset", I, "Forgot password -> reset with code -> login with new password",
       "new password N3w!Passw0rd", "new password works, old password fails")
    register(client, "reset@test.com")
    client.post("/api/auth/forgot-password", json={"email": "reset@test.com"})
    r = client.post("/api/auth/reset-password", json={
        "email": "reset@test.com", "code": sent_codes["reset@test.com"], "new_password": "N3w!Passw0rd"})
    new = login(client, "reset@test.com", "N3w!Passw0rd")
    old = login(client, "reset@test.com", STRONG_PASSWORD)
    tc.actual(f"reset={r.status_code}; new login={new.status_code}; old login={old.status_code}")
    assert r.status_code == 204 and new.status_code == 200 and old.status_code == 401


ADMIN_ENDPOINTS = [
    ("get", "/api/admin/dashboard"),
    ("get", "/api/admin/users"),
    ("get", "/api/admin/detections"),
    ("get", "/api/admin/analytics"),
    ("get", "/api/admin/reported-urls"),
    ("get", "/api/admin/user-blocked-urls"),
    ("post", "/api/admin/extension-reports/1/approve"),
    ("delete", "/api/admin/users/1"),
]


@pytest.mark.parametrize("method, path", ADMIN_ENDPOINTS)
def test_non_admin_forbidden(client, tc, user_token, method, path):
    tc("Access control", I, f"Normal user calls admin endpoint {method.upper()} {path}",
       "user JWT", "403 Admin access required")
    r = getattr(client, method)(path, headers=auth(user_token))
    tc.actual(f"{r.status_code}; {r.json().get('detail')}")
    assert r.status_code == 403


@pytest.mark.parametrize("method, path", ADMIN_ENDPOINTS[:3])
def test_anonymous_admin_unauthorised(client, tc, method, path):
    tc("Access control", I, f"No token on admin endpoint {method.upper()} {path}",
       "no Authorization header", "401")
    r = getattr(client, method)(path)
    tc.actual(str(r.status_code))
    assert r.status_code == 401


def test_admin_can_access(client, tc, admin_token):
    tc("Access control", I, "Admin can open the admin dashboard and user list", "admin JWT",
       "200 for both")
    a = client.get("/api/admin/dashboard", headers=auth(admin_token))
    b = client.get("/api/admin/users", headers=auth(admin_token))
    tc.actual(f"{a.status_code}/{b.status_code}")
    assert a.status_code == b.status_code == 200
