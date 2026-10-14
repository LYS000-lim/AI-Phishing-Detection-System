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


def test_admin_global_block_cycle(client, tc, admin_token, user_token):
    tc("Global block", I,
       "Admin pastes URL -> blocked for all users -> listed -> admin unblocks",
       "POST /api/admin/global-blocks https://paste-phish.xyz/login?id=1",
       "201, everyone blocked, duplicate 409, non-admin 403, unblocked after delete")
    h = auth(admin_token)
    add = client.post("/api/admin/global-blocks", headers=h,
                      json={"url": "https://paste-phish.xyz/login?id=1", "attack_type": "Credential Theft"})
    dup = client.post("/api/admin/global-blocks", headers=h, json={"url": "paste-phish.xyz"})
    listed = client.get("/api/admin/global-blocks", headers=h).json()
    anon = client.get("/api/extension/check-blacklist", params={"url": "http://paste-phish.xyz/x"}).json()
    signed_in = client.get("/api/extension/check-blacklist", params={"url": "http://paste-phish.xyz/"},
                           headers=auth(user_token)).json()
    forbidden = client.post("/api/admin/global-blocks", headers=auth(user_token), json={"url": "a-site.xyz"})
    removed = client.delete(f"/api/admin/global-blocks/{add.json()['id']}", headers=h)
    cleared = client.get("/api/extension/check-blacklist", params={"url": "http://paste-phish.xyz/x"}).json()
    tc.actual(f"add={add.status_code} domain={add.json().get('domain')}; dup={dup.status_code}; "
              f"listed={len(listed)} source={listed[0]['source']}; anon blocked={anon['blocked']}; "
              f"user blocked={signed_in['blocked']}; non-admin={forbidden.status_code}; "
              f"delete={removed.status_code}; after={cleared['blocked']}")
    assert add.status_code == 201 and add.json()["domain"] == "paste-phish.xyz"
    assert dup.status_code == 409
    assert len(listed) == 1 and listed[0]["source"] == "Admin (Manual)"
    assert anon["blocked"] is True and anon["blocked_by"] == "admin"
    assert signed_in["blocked"] is True
    assert forbidden.status_code == 403
    assert removed.status_code == 204 and cleared["blocked"] is False


def test_admin_global_block_validation(client, tc, admin_token):
    tc("Global block", I, "Invalid URL rejected; well-known site needs confirmation",
       "'not a url', then https://www.google.com without/with confirm",
       "400; needs_confirm then 201")
    h = auth(admin_token)
    bad = client.post("/api/admin/global-blocks", headers=h, json={"url": "not a url"})
    warn = client.post("/api/admin/global-blocks", headers=h, json={"url": "https://www.google.com"})
    forced = client.post("/api/admin/global-blocks", headers=h,
                         json={"url": "https://www.google.com", "confirm": True})
    tc.actual(f"bad={bad.status_code}; first={warn.status_code} needs_confirm={warn.json().get('needs_confirm')}; "
              f"confirmed={forced.status_code}")
    assert bad.status_code == 400
    assert warn.json().get("needs_confirm") is True
    assert forced.status_code == 201


def test_reported_urls_count_and_sort(client, tc, admin_token):
    tc("Report & blacklist", I, "Reported URLs show per-site report count and sort by most reported",
       "3 reports of many-reports.xyz, 1 of once.xyz; sort=most_reported", "first row count=3")
    for path in ("/a", "/b", "/c"):
        client.post("/api/extension/report", json={"url": f"http://many-reports.xyz{path}"})
    client.post("/api/extension/report", json={"url": "http://once.xyz"})
    data = client.get("/api/admin/reported-urls", params={"sort": "most_reported"},
                      headers=auth(admin_token)).json()
    first = data["items"][0]
    tc.actual(f"first={first['url']} count={first['report_count']}; last count={data['items'][-1]['report_count']}")
    assert first["report_count"] == 3 and "many-reports.xyz" in first["url"]
    assert data["items"][-1]["report_count"] == 1


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
