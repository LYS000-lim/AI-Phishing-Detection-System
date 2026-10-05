"""
Shared pytest setup for the PhishGuard API test suite.

- Points the app at a throw-away SQLite file (PHISHGUARD_DB_URL is read when
  app.database is imported, so it is set before any app import). The real
  backend/phishguard.db is never touched.
- Every test starts with empty tables.
- Outgoing email is replaced by a stub that records the 6-digit reset code,
  so tests never send real mail (backend/.env holds live SMTP settings).
- Each test describes itself through the `tc` fixture; at the end of the run
  the descriptions and outcomes are written to outputs/test_cases.csv.

Run from the repository root:  .venv/Scripts/python -m pytest backend/tests -v
"""
import csv
import os
import sys
import tempfile

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_TMP_DIR = tempfile.mkdtemp(prefix="phishguard_test_")
os.environ["PHISHGUARD_DB_URL"] = "sqlite:///" + os.path.join(_TMP_DIR, "test.db").replace("\\", "/")
sys.path.insert(0, os.path.join(ROOT, "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from app import email_utils, routes_auth  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402

STRONG_PASSWORD = "Str0ng!Pass"
CSV_PATH = os.path.join(ROOT, "outputs", "test_cases.csv")
_TYPE_PREFIX = {"Unit": "UT", "Integration": "IT", "Security": "ST"}
_CASES = []


# ---------------------------------------------------------------------------
# App / database fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def sent_codes(monkeypatch):
    """email -> last reset code "sent". Replaces real SMTP delivery."""
    codes = {}
    monkeypatch.setattr(routes_auth, "send_password_reset_code",
                        lambda to, code, ttl: codes.__setitem__(to, code))
    monkeypatch.setattr(email_utils, "SMTP_HOST", None)
    return codes


@pytest.fixture
def client(sent_codes):
    with TestClient(app) as c:
        yield c


def register(client, email, password=STRONG_PASSWORD, name="Test User"):
    return client.post("/api/auth/register",
                       json={"full_name": name, "email": email, "password": password})


def login(client, email, password=STRONG_PASSWORD):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_token(client):
    """The first registered account becomes the admin."""
    register(client, "admin@test.com", name="Admin")
    return login(client, "admin@test.com").json()["access_token"]


@pytest.fixture
def user_token(client, admin_token):
    register(client, "user@test.com", name="Normal User")
    return login(client, "user@test.com").json()["access_token"]


# ---------------------------------------------------------------------------
# Test-case documentation -> outputs/test_cases.csv
# ---------------------------------------------------------------------------
class _Case:
    def __init__(self, item):
        self.item = item
        self.data = {}

    def __call__(self, feature, type_, description, input_, expected):
        self.data.update(feature=feature, type=type_, description=description,
                         input=input_, expected=expected)

    def actual(self, text):
        self.data["actual"] = text


@pytest.fixture
def tc(request):
    case = _Case(request.node)
    request.node._tc = case
    return case


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    case = getattr(item, "_tc", None)
    if case is None or not case.data:
        return
    if rep.when == "call" or (rep.when == "setup" and rep.failed):
        actual = case.data.get("actual", "")
        if rep.failed:
            msg = getattr(rep.longrepr, "reprcrash", None)
            actual = f"FAILED: {msg.message if msg else rep.longrepr}"[:300]
        path, line, _ = item.location
        _CASES.append({
            **case.data, "actual": actual,
            "result": "Pass" if rep.passed else "Fail",
            "where": f"{path.replace(os.sep, '/')}:{line + 1}",
        })


def pytest_sessionfinish(session, exitstatus):
    if not _CASES:
        return
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    counters = {}
    order = {"Unit": 0, "Integration": 1, "Security": 2}
    rows = sorted(_CASES, key=lambda c: order.get(c["type"], 9))
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ID", "Feature", "Type", "Test case description", "Input",
                    "Expected result", "Actual result", "Pass/Fail", "Test function"])
        for c in rows:
            prefix = _TYPE_PREFIX.get(c["type"], "TC")
            counters[prefix] = counters.get(prefix, 0) + 1
            w.writerow([f"{prefix}-{counters[prefix]:02d}", c["feature"], c["type"],
                        c["description"], c["input"], c["expected"], c["actual"],
                        c["result"], c["where"]])
