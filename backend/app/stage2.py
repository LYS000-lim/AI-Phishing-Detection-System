"""
Stage-2 model: the URL model's score combined with the domain's age.

Stage 1 (the Random Forest on 22 URL features) only reads the address. Stage
2 is a logistic regression trained by notebooks/train_stage2.py on URLs that
stage 1 never saw, with two inputs:
    log-odds of the stage-1 score, and log(1 + domain age in days)
so a domain registered days ago pushes the phishing probability up and a
domain held for many years pushes it down, by an amount the model learned.
Its own thresholds (outputs/stage2_model.joblib) were tuned so legitimate
URLs are warned no more often than by stage 1.

It applies to a URL whose registered domain belongs to one owner: not a
shared hosting platform (the age would be the platform's), not a link
shortener, not an IP address - and only when the domain age is found within
LOOKUP_BUDGET seconds (domain_age.py). Otherwise stage 1 decides alone.

Set PHISHGUARD_STAGE2=0 to switch it off (the test suite does).
"""
import ipaddress
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone

import joblib
import numpy as np

from . import domain_age

LOOKUP_BUDGET = 6.0
_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "outputs", "stage2_model.joblib")
_bundle = None
_lock = threading.Lock()
# Lookups that miss the budget keep running here and fill the cache.
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="domain-age")


def _load():
    global _bundle
    with _lock:
        if _bundle is None:
            _bundle = joblib.load(_PATH) if os.path.exists(_PATH) else False
    return _bundle


def enabled() -> bool:
    return os.environ.get("PHISHGUARD_STAGE2", "1") != "0" and bool(_load())


def thresholds() -> dict:
    return _load()["thresholds"]


def features(stage1, age_days) -> np.ndarray:
    """Same inputs as notebooks/train_stage2.py."""
    p = np.clip(np.asarray(stage1, dtype=float), 1e-4, 1 - 1e-4)
    return np.column_stack([np.log(p / (1 - p)),
                            np.log1p(np.clip(np.asarray(age_days, dtype=float), 0, None))])


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _age(domain: str):
    future = _pool.submit(domain_age.registered, domain)
    try:
        return future.result(timeout=LOOKUP_BUDGET)
    except FutureTimeout:
        return None


def score(stage1_p: float, domain: str):
    """{"p", "age_days", "registered", "level", "thresholds", "url_logodds",
    "age_logodds"} for the domain, or None when stage 2 cannot be used."""
    if not enabled() or not domain or "." not in domain or _is_ip(domain):
        return None
    registered = _age(domain)
    if registered is None:
        return None
    days = max((datetime.now(timezone.utc) - registered).days, 0)
    bundle = _load()
    model = bundle["model"]
    x = features([stage1_p], [days])
    p = float(model.predict_proba(x)[0][1])
    t = bundle["thresholds"]
    return {
        "p": round(p, 4),
        "age_days": days,
        "registered": registered.date().isoformat(),
        "domain": domain,
        "level": "phishing" if p >= t["phishing"] else "uncertain" if p >= t["uncertain"] else "legitimate",
        "thresholds": t,
        # Each input's push on the log-odds (positive = towards phishing).
        "url_logodds": round(float(model.coef_[0][0] * x[0][0]), 3),
        "age_logodds": round(float(model.coef_[0][1] * x[0][1]), 3),
    }


def describe_age(days: int) -> str:
    years = days / 365.25
    if days < 30:
        return f"only {days} day{'s' if days != 1 else ''} ago"
    if days < 365:
        return f"about {round(days / 30.4)} months ago"
    return f"about {years:.0f} year{'s' if round(years) != 1 else ''} ago"
