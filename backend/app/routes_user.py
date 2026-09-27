from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from typing import List, Optional

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import Integer, desc, func
from sqlalchemy.orm import Session

from .auth import current_user, hash_password, verify_password
from .allowlist import is_trusted, matched_domain
from .database import get_db
from .explanations import (
    build_evidence, build_reason_bullets,
    plain_text_explanation, risk_level,
)
from .features import FEATURE_ORDER, extract_features, feature_vector
from .ml_state import classify_vec, get_lime_explainer, get_shap_explainer, model_info, MODEL
from .models import Detection, ReportedURL, User, UserBlockedURL
from .schemas import (
    BatchRequest, DetectionOut, PasswordChange, ProfileUpdate,
    ReportURLRequest, ReportedURLOut,
    URLRequest, UserOut,
)

from .phishing_type import detect_phishing_type

router = APIRouter(tags=["user"])


# ---------------------------------------------------------------------------
# Scan / predict
# ---------------------------------------------------------------------------
def _predict_and_log(
    url: str,
    user: User,
    db: Session,
    ip: Optional[str] = None,
    source: str = "website",
) -> dict:
    # Reputation-list bypass: well-known trusted domains skip ML
    # classification entirely. This is a separate result state from an ML
    # legitimate prediction and therefore returns trusted_domain=True.
    if is_trusted(url):
        domain = matched_domain(url)
        features = extract_features(url)
        record = Detection(
            user_id=user.id,
            url=url,
            prediction="legitimate",
            label=0,
            confidence=1.0,
            phishing_probability=0.0,
            risk_level="Low",
            model_used="TrustedAllowlist",
            ip_address=ip,
            source=source,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return {
            "id": record.id,
            "url": url,
            "prediction": "legitimate",
            "label": 0,
            "confidence": 1.0,
            "phishing_probability": 0.0,
            "legitimate_probability": 1.0,
            "risk_level": "Low",
            "model_used": "TrustedAllowlist",
            "trusted_domain": True,
            "matched_domain": domain,
            "security_status": "Trusted Website",
            "features": features,
            "attack_type": None,
            "created_at": record.created_at.isoformat(),
        }

    if MODEL is None:
        raise HTTPException(
            503,
            "Trained model is not available yet. Run "
            "`python notebooks/train_and_compare.py` against the "
            "PhiUSIIL CSV to generate outputs/deployment_model.joblib, "
            "then restart the API. (Trusted domains still work via the "
            "reputation allowlist.)",
        )

    vec = feature_vector(url)
    features = extract_features(url)

    # Tuned thresholds + the missing-HTTPS softening live in one place
    # (explanations.classify). `label`/`phishing_probability` still store
    # the model's raw decision, so dashboard/aggregate stats keep reporting
    # true model behaviour -- only prediction/risk_level are softened.
    verdict = classify_vec(vec, features, url)
    label = verdict["label"]                           # 0=Legit, 1=Phish
    p_phish = verdict["p_phish"]
    confidence = verdict["confidence"]
    prediction = verdict["prediction"]
    risk = verdict["risk"]

    attack_type = None
    if prediction == "phishing":
        attack_type = detect_phishing_type(url, features)

    record = Detection(
        user_id=user.id,
        url=url,
        prediction=prediction,
        label=label,
        confidence=round(confidence, 4),
        phishing_probability=round(p_phish, 4),
        risk_level=risk,
        model_used=model_info()["name"],
        attack_type=attack_type["category"] if attack_type else None,
        ip_address=ip,
        source=source,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "id": record.id,
        "url": url,
        "prediction": prediction,
        "label": label,
        "confidence": round(confidence, 4),
        "phishing_probability": round(p_phish, 4),
        "legitimate_probability": round(1 - p_phish, 4),
        "risk_level": risk,
        "model_used": model_info()["name"],
        "trusted_domain": False,
        "uncertain_reason": verdict["uncertain_reason"],
        "legit_reason": verdict["legit_reason"],
        "reputation": verdict["reputation"],
        "features": features,
        "attack_type": attack_type,
        "created_at": record.created_at.isoformat(),
    }


@router.post("/api/scan")
def scan(
    req: URLRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    try:
        return _predict_and_log(
            req.url, user, db, ip=request.client.host if request.client else None,
        )
    except Exception as exc:
        raise HTTPException(422, f"Could not process URL: {exc}")


@router.post("/api/scan/batch")
def scan_batch(
    req: BatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    ip = request.client.host if request.client else None
    results, errors = [], []
    for u in req.urls:
        try:
            results.append(_predict_and_log(u, user, db, ip=ip))
        except Exception as exc:
            errors.append({"url": u, "error": str(exc)})
    return {"count": len(results), "results": results, "errors": errors}


# ---------------------------------------------------------------------------
# Individual explanation (SHAP + LIME + plain-text summary)
# ---------------------------------------------------------------------------
@router.post("/api/explain")
def explain(req: URLRequest, user: User = Depends(current_user)):
    # Trusted-domain results are decided by reputation verification, not by
    # the ML model. Return a dedicated explanation state with no SHAP/LIME.
    if is_trusted(req.url):
        domain = matched_domain(req.url)
        return {
            "url": req.url,
            "prediction": "legitimate",
            "risk_level": "Low",
            "confidence": 1.0,
            "phishing_probability": 0.0,
            "legitimate_probability": 1.0,
            "model_used": "TrustedAllowlist",
            "trusted_domain": True,
            "matched_domain": domain,
            "security_status": "Trusted Website",
            "security_analysis": [
                "This website has been verified as an official trusted domain.",
                "The URL structure does not contain suspicious characteristics commonly observed in phishing websites.",
            ],
            "why_detected": [
                f"The official domain '{domain}' matched the trusted-domain allowlist.",
                "Trusted-domain verification completed successfully, so an ML explanation was not required.",
            ],
            "plain_text": (
                f"The official domain '{domain}' matched the trusted-domain "
                "allowlist. ML classification was not required."
            ),
            "attack_analysis": None,
            "evidence": [],
            "shap": {
                "note": "Trusted-domain verification - SHAP not computed.",
                "top_features": [],
            },
            "lime": {
                "note": "Trusted-domain verification - LIME not computed.",
                "top_rules": [],
            },
        }

    if MODEL is None:
        raise HTTPException(503, "Trained model is not available.")

    try:
        vec = feature_vector(req.url)
        features = extract_features(req.url)
    except Exception as exc:
        raise HTTPException(422, f"Could not process URL: {exc}")

    verdict = classify_vec(vec, features, req.url)
    label = verdict["label"]
    p_phish = verdict["p_phish"]
    prediction = verdict["prediction"]
    risk = verdict["risk"]
    uncertain_reputable = verdict["uncertain_reason"] == "reputable_domain"
    uncertain_https = verdict["uncertain_reason"] == "https_only"
    uncertain_borderline = verdict["uncertain_reason"] == "borderline"

    # SHAP contributions for class 1 (phishing).
    shap_exp = get_shap_explainer()
    shap_vals = shap_exp.shap_values(vec)
    arr = np.asarray(shap_vals)
    if arr.ndim == 3:                       # (samples, features, classes)
        contrib = arr[0, :, 1]
    elif isinstance(shap_vals, list):       # [class0, class1]
        contrib = np.asarray(shap_vals[1])[0]
    else:                                   # single-class output
        contrib = arr[0]

    shap_out = sorted(
        (
            {"feature": f, "shap_value": round(float(v), 5)}
            for f, v in zip(FEATURE_ORDER, contrib)
        ),
        key=lambda d: abs(d["shap_value"]),
        reverse=True,
    )[:10]

    # LIME local rules for the phishing class.
    lime_exp = get_lime_explainer()
    explanation = lime_exp.explain_instance(
        vec[0], MODEL.predict_proba, num_features=10, labels=[1],
    )
    lime_out = [
        {"rule": rule, "weight": round(float(w), 5)}
        for rule, w in explanation.as_list(label=1)
    ]

    attack_analysis = (
        detect_phishing_type(req.url, features)
        if prediction == "phishing"
        else None
    )

    if uncertain_reputable:
        # The model scored the URL text as phishing, but the registered
        # domain is a well-established website, so the verdict is capped.
        rep = verdict["reputation"]
        why_detected = build_reason_bullets(
            "phishing", features, shap_out, attack_analysis=None, limit=3,
        )
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=3)
        plain = (
            "Suspicious. The address pattern resembles phishing, but it belongs "
            f"to {rep['domain']}, a well-established "
            f"website (ranked #{rep['rank']:,} globally), so it is not treated as "
            "confirmed phishing. Make sure the domain is exactly "
            f"{rep['domain']} before entering passwords or payment details."
        )
        security_analysis = [
            f"The registered domain {rep['domain']} is among the most visited "
            f"websites worldwide (Tranco rank #{rep['rank']:,}).",
            "Login, account and payment pages of real services often have "
            "address patterns similar to phishing pages, so a URL-pattern "
            "score alone is not treated as proof for an established domain.",
        ]
    elif uncertain_borderline:
        # Score between the tuned "uncertain" and "phishing" thresholds:
        # some phishing-like signals, but not enough for a hard verdict.
        why_detected = build_reason_bullets(
            "phishing", features, shap_out, attack_analysis=None, limit=3,
        )
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=3)
        plain = (
            f"Suspicious (low-confidence result, {p_phish:.0%} phishing score). "
            "Some URL characteristics resemble phishing, but not strongly "
            "enough to confirm it. This is not a confirmed phishing detection - "
            "check the domain name carefully before entering passwords or "
            "payment details."
        )
        security_analysis = [
            "The model's phishing score for this URL falls in the borderline "
            "range: above what is treated as safe, below the confidence needed "
            "for a phishing verdict.",
            "Low-confidence results are shown as suspicious instead of "
            "phishing to avoid falsely accusing legitimate websites.",
        ]
    elif uncertain_https:
        # build_reason_bullets/build_evidence/plain_text_explanation only
        # know "phishing" vs. "legitimate" wording -- "uncertain" gets its
        # own bespoke text here instead of falling into their legitimate-ish
        # else-branch, which would read as a false all-clear.
        why_detected = [
            "The model's own top-weighted signal for this URL is the absence "
            "of a secure HTTPS connection, not a confirmed phishing pattern.",
            "Testing the same URL as if it were served over HTTPS flips the "
            "model's verdict to legitimate, meaning the missing-HTTPS signal "
            "alone is driving the phishing call.",
            "Missing HTTPS is a real risk factor genuine phishing sites often "
            "share, but many legitimate (often older or informational) sites "
            "still don't use it, so this alone isn't treated as proof.",
        ]
        evidence = build_evidence("phishing", features, shap_out, lime_out, limit=3)
        plain = (
            "Suspicious (low-confidence result). The model's score is driven "
            "mainly by the lack of an HTTPS connection, which "
            "is a real but not conclusive risk signal. This is not a confirmed "
            "phishing detection - check the domain name carefully before "
            "entering passwords or payment details."
        )
        security_analysis = [
            "The model's phishing call for this URL is driven almost entirely "
            "by the missing HTTPS connection, not by other structural red flags.",
            "This is shown as suspicious rather than a confirmed phishing "
            "result, since many legitimate sites still don't use HTTPS.",
        ]
    elif verdict["legit_reason"] == "http_reputable":
        # Plain-http page on a well-established domain whose only warning
        # signal was the missing HTTPS (ml_state.classify_vec HTTP rule).
        rep = verdict["reputation"]
        why_detected = [
            f"The registered domain {rep['domain']} is a well-established website "
            f"(Tranco rank #{rep['rank']:,}).",
            "The only warning signal for this URL is the missing HTTPS connection: "
            "the same address served over HTTPS scores as legitimate.",
        ]
        # Show the missing-HTTPS signal the text refers to, then the
        # strongest legitimate signals.
        https_card = [
            e for e in build_evidence("phishing", features, shap_out, lime_out, limit=len(shap_out))
            if e["feature"] == "IsHTTPS"
        ]
        evidence = https_card + build_evidence("legitimate", features, shap_out, lime_out, limit=3 - len(https_card))
        plain = (
            f"Legitimate. This page belongs to {rep['domain']}, a well-established "
            "website, and shows no phishing pattern other than using plain HTTP. "
            "The connection is not encrypted, so avoid entering passwords or "
            "payment details unless the page switches to https://."
        )
        security_analysis = [
            "No phishing indicators were found apart from the missing HTTPS connection.",
            "HTTP pages are not encrypted: data you type can be read in transit.",
        ]
    else:
        why_detected = build_reason_bullets(
            prediction,
            features,
            shap_out,
            attack_analysis=attack_analysis,
            limit=4,
        )
        evidence = build_evidence(
            prediction,
            features,
            shap_out,
            lime_out,
            limit=3,
        )
        plain = plain_text_explanation(prediction, risk, shap_out)

        security_analysis = None
        if prediction == "legitimate":
            security_analysis = [
                "No significant phishing indicators were detected by the ML model.",
                "The URL structure matches characteristics commonly associated with legitimate websites.",
            ]

    return {
        "url": req.url,
        "prediction": prediction,
        "risk_level": risk,
        "confidence": round(verdict["confidence"], 4),
        "uncertain_reason": verdict["uncertain_reason"],
        "legit_reason": verdict["legit_reason"],
        "reputation": verdict["reputation"],
        "phishing_probability": round(p_phish, 4),
        "legitimate_probability": round(1 - p_phish, 4),
        "model_used": model_info()["name"],
        "trusted_domain": False,
        "plain_text": plain,
        "attack_analysis": attack_analysis,
        "security_analysis": security_analysis,
        "why_detected": why_detected,
        "evidence": evidence,
        # Raw values are retained for analytics/backward compatibility, but
        # the redesigned Scanner.jsx displays only the compact evidence list.
        "shap": {
            "note": "Positive values push toward PHISHING; negative toward LEGITIMATE.",
            "top_features": shap_out,
        },
        "lime": {
            "note": "Positive weights support PHISHING; negative support LEGITIMATE.",
            "top_rules": lime_out,
        },
    }


# ---------------------------------------------------------------------------
# Personal history + dashboard
# ---------------------------------------------------------------------------
def _date_range_bounds(date_from: Optional[str], date_to: Optional[str]):
    """Parse YYYY-MM-DD query params into inclusive-day datetime bounds."""
    start = end = None
    if date_from:
        try:
            start = datetime.combine(date.fromisoformat(date_from), time.min)
        except ValueError:
            raise HTTPException(400, "Invalid date_from (expected YYYY-MM-DD)")
    if date_to:
        try:
            end = datetime.combine(date.fromisoformat(date_to), time.max)
        except ValueError:
            raise HTTPException(400, "Invalid date_to (expected YYYY-MM-DD)")
    return start, end


@router.get("/api/detections")
def my_detections(
    page: int = 1,
    page_size: int = 20,
    q: Optional[str] = None,
    result: Optional[str] = None,          # "phishing" | "legitimate"
    risk: Optional[str] = None,            # "Low" | "Medium" | "High"
    attack_type: Optional[str] = None,
    date_from: Optional[str] = None,       # "YYYY-MM-DD"
    date_to: Optional[str] = None,
    source: Optional[str] = None,          # "website" | "extension"
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = db.query(Detection).filter(Detection.user_id == user.id)
    if q:
        query = query.filter(Detection.url.ilike(f"%{q}%"))
    if result in ("phishing", "legitimate"):
        query = query.filter(Detection.prediction == result)
    if risk in ("Low", "Medium", "High"):
        query = query.filter(Detection.risk_level == risk)
    if attack_type:
        query = query.filter(Detection.attack_type == attack_type)
    if source in ("website", "extension"):
        query = query.filter(Detection.source == source)

    start, end = _date_range_bounds(date_from, date_to)
    if start:
        query = query.filter(Detection.created_at >= start)
    if end:
        query = query.filter(Detection.created_at <= end)

    total = query.count()
    rows = (
        query.order_by(desc(Detection.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "items": [DetectionOut.model_validate(r).model_dump(mode="json") for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.get("/api/detections/history-summary")
def detections_history_summary(
    source: Optional[str] = None,          # "website" | "extension"
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """
    Feeds the Browser Extension Detection History section: stat cards,
    a 7-day trend, and attack-category / risk-level breakdowns, optionally
    scoped to one source so the page can filter All / Website / Extension.
    """
    q = db.query(Detection).filter(Detection.user_id == user.id)
    if source in ("website", "extension"):
        q = q.filter(Detection.source == source)

    total = q.count()
    phishing = q.filter(Detection.label == 1).count()
    legitimate = total - phishing
    high_risk = q.filter(Detection.risk_level == "High").count()

    since7 = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)
    trend_query = (
        db.query(
            func.date(Detection.created_at).label("day"),
            func.sum((Detection.label == 1).cast(Integer)).label("phishing"),
            func.sum((Detection.label == 0).cast(Integer)).label("legitimate"),
        )
        .filter(Detection.user_id == user.id, Detection.created_at >= since7)
    )
    if source in ("website", "extension"):
        trend_query = trend_query.filter(Detection.source == source)
    trend_rows = trend_query.group_by("day").order_by("day").all()
    trend_7d = [
        {"day": r.day, "phishing": int(r.phishing or 0),
         "legitimate": int(r.legitimate or 0)}
        for r in trend_rows
    ]

    attack_query = (
        db.query(Detection.attack_type, func.count(Detection.id).label("n"))
        .filter(Detection.user_id == user.id, Detection.attack_type.isnot(None))
    )
    if source in ("website", "extension"):
        attack_query = attack_query.filter(Detection.source == source)
    attack_rows = attack_query.group_by(Detection.attack_type).order_by(desc("n")).all()
    attack_category_frequency = [
        {"category": r[0], "count": int(r[1])} for r in attack_rows
    ]

    risk_query = (
        db.query(Detection.risk_level, func.count(Detection.id).label("n"))
        .filter(Detection.user_id == user.id)
    )
    if source in ("website", "extension"):
        risk_query = risk_query.filter(Detection.source == source)
    risk_counts = {r[0]: int(r[1]) for r in risk_query.group_by(Detection.risk_level).all()}

    return {
        "totals": {
            "total": total, "phishing": phishing,
            "legitimate": legitimate, "high_risk": high_risk,
        },
        "trend_7d": trend_7d,
        "attack_category_frequency": attack_category_frequency,
        "risk_distribution": {
            "Low": risk_counts.get("Low", 0),
            "Medium": risk_counts.get("Medium", 0),
            "High": risk_counts.get("High", 0),
        },
    }


_SOURCE_DISPLAY = [
    ("website", "Website Scanner"),
    ("extension", "Chrome Extension"),
]


def _resolve_window(days: int, date_from: Optional[str], date_to: Optional[str]):
    """Shared by the admin and user dashboard-visuals endpoints: resolves the
    (since, until) datetime window from either an explicit start/end date
    range or a day-count fallback."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if date_from and date_to:
        try:
            since = datetime.strptime(date_from, "%Y-%m-%d")
            until = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)
            return since, until
        except ValueError:
            pass
    days = max(1, min(days, 90))
    return now - timedelta(days=days), now


def _feature_distribution(urls: List[str]) -> dict:
    """Shared with the admin dashboard's 'Important URL Characteristics'
    chart - counts how many of the given URLs exhibit each characteristic."""
    dist = {
        "long_url": 0, "https": 0, "ip_domain": 0,
        "suspicious_keywords": 0, "many_subdomains": 0,
    }
    suspicious_words = ("login", "verify", "secure", "account", "update",
                         "bank", "confirm", "signin", "password", "billing")
    for url in urls:
        f = extract_features(url)
        if f["URLLength"] > 75:
            dist["long_url"] += 1
        if f["IsHTTPS"] == 1:
            dist["https"] += 1
        if f["IsDomainIP"] == 1:
            dist["ip_domain"] += 1
        if any(w in url.lower() for w in suspicious_words):
            dist["suspicious_keywords"] += 1
        if f["NoOfSubDomain"] >= 3:
            dist["many_subdomains"] += 1
    return dist


def _source_distribution(sources: List[str]) -> list:
    """Shared with the admin dashboard's 'Detection Source Distribution'
    chart - percentage breakdown of where a set of detections came from."""
    total = len(sources)
    counts = Counter(sources)
    return [
        {
            "source": label,
            "count": counts.get(key, 0),
            "percentage": round(counts.get(key, 0) / total * 100, 1) if total else 0.0,
        }
        for key, label in _SOURCE_DISPLAY
    ]


@router.get("/api/detections/dashboard-visuals")
def detections_dashboard_visuals(
    days: int = 14,
    date_from: Optional[str] = None,       # "YYYY-MM-DD", overrides `days` with `date_to`
    date_to: Optional[str] = None,         # "YYYY-MM-DD"
    source: Optional[str] = None,          # "website" | "extension"
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """
    Feeds the interactive chart section of the User Dashboard (Threat Trend,
    Detection Result Overview, Important URL Characteristics, Attack Category
    Analysis, Detection Source Distribution) - same shape as the admin
    dashboard's 'visuals' block, scoped to this user and filterable by time
    window / source. Kept separate from /detections/summary (lifetime KPI
    cards) and /detections/history-summary (Browser Extension History page)
    so neither of those is affected by this filtering.
    """
    since, until = _resolve_window(days, date_from, date_to)

    q = db.query(Detection).filter(
        Detection.user_id == user.id,
        Detection.created_at >= since, Detection.created_at < until,
    )
    if source in ("website", "extension"):
        q = q.filter(Detection.source == source)
    rows = q.all()

    phishing = sum(1 for r in rows if r.label == 1)
    legitimate = len(rows) - phishing

    trend_map = {}
    for r in rows:
        day = r.created_at.date().isoformat()
        bucket = trend_map.setdefault(day, {"phishing": 0, "legitimate": 0})
        bucket["phishing" if r.label == 1 else "legitimate"] += 1
    trend = [
        {"day": day, **counts} for day, counts in sorted(trend_map.items())
    ]

    attack_counts = Counter(r.attack_type for r in rows if r.attack_type)
    attack_category_frequency = [
        {"category": category, "count": count}
        for category, count in attack_counts.most_common()
    ]

    # Source distribution ignores the `source` filter itself (that's the
    # whole point of this chart), but still respects the time window.
    since_rows = (
        db.query(Detection.source)
        .filter(
            Detection.user_id == user.id,
            Detection.created_at >= since, Detection.created_at < until,
        )
        .all()
    )

    return {
        "date_from": since.date().isoformat(),
        "date_to": (until - timedelta(days=1)).date().isoformat(),
        "trend": trend,
        "result_counts": {"phishing": phishing, "legitimate": legitimate},
        "feature_distribution": _feature_distribution([r.url for r in rows]),
        "attack_category_frequency": attack_category_frequency,
        "source_distribution": _source_distribution([s for (s,) in since_rows]),
    }


@router.get("/api/detections/summary")
def personal_summary(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """
    Feeds the User Dashboard: totals, feature-distribution counts,
    and a small window of recent scans.
    """
    q = db.query(Detection).filter(Detection.user_id == user.id)
    total = q.count()
    phish = q.filter(Detection.label == 1).count()
    legit = total - phish

    # Feature-distribution counts across the user's own scans.
    dist = {
        "long_url": 0, "https": 0, "ip_domain": 0,
        "suspicious_keywords": 0, "many_subdomains": 0,
    }
    suspicious_words = ("login", "verify", "secure", "account", "update",
                         "bank", "confirm", "signin", "password", "billing")
    for row in q.all():
        f = extract_features(row.url)
        if f["URLLength"] > 75:
            dist["long_url"] += 1
        if f["IsHTTPS"] == 1:
            dist["https"] += 1
        if f["IsDomainIP"] == 1:
            dist["ip_domain"] += 1
        if any(w in row.url.lower() for w in suspicious_words):
            dist["suspicious_keywords"] += 1
        if f["NoOfSubDomain"] >= 3:
            dist["many_subdomains"] += 1

    recent = (q.order_by(desc(Detection.created_at)).limit(10).all())

    month_start = datetime.now(timezone.utc).replace(
        tzinfo=None, day=1, hour=0, minute=0, second=0, microsecond=0,
    )
    phishing_this_month = q.filter(
        Detection.label == 1, Detection.created_at >= month_start,
    ).count()

    # Detection trend for the last 7 days (mirrors the admin dashboard's
    # 14-day trend, scoped to this user).
    since7 = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)
    trend_rows = (
        db.query(
            func.date(Detection.created_at).label("day"),
            func.sum((Detection.label == 1).cast(Integer)).label("phishing"),
            func.sum((Detection.label == 0).cast(Integer)).label("legitimate"),
        )
        .filter(Detection.user_id == user.id, Detection.created_at >= since7)
        .group_by("day").order_by("day").all()
    )
    trend_7d = [
        {"day": r.day, "phishing": int(r.phishing or 0),
         "legitimate": int(r.legitimate or 0)}
        for r in trend_rows
    ]

    return {
        "totals": {"total": total, "phishing": phish, "legitimate": legit},
        "feature_distribution": dist,
        "recent": [DetectionOut.model_validate(r).model_dump(mode="json")
                   for r in recent],
        "trend_7d": trend_7d,
        "phishing_this_month": phishing_this_month,
    }


@router.get("/api/detections/{detection_id}")
def detection_detail(
    detection_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    row = db.query(Detection).filter(Detection.id == detection_id).first()
    if not row:
        raise HTTPException(404, "Detection not found")
    if row.user_id != user.id and user.role != "admin":
        raise HTTPException(403, "Not permitted")
    return DetectionOut.model_validate(row)

# ---------------------------------------------------------------------------
# Report phishing URL
# ---------------------------------------------------------------------------

@router.post("/api/report-url", response_model=ReportedURLOut)
def report_url(
    req: ReportURLRequest,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    existing = (
        db.query(ReportedURL)
        .filter(ReportedURL.url == req.url)
        .first()
    )

    if existing:
        raise HTTPException(
            409,
            "This URL has already been reported."
        )

    reported = ReportedURL(
        user_id=user.id,
        url=req.url,
        attack_type=req.attack_type,
        detection_reason=req.detection_reason,
    )

    db.add(reported)
    db.commit()
    db.refresh(reported)

    return reported


@router.get("/api/my-reports", response_model=List[ReportedURLOut])
def my_reports(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """The signed-in user's own reported URLs (their side of the same
    ReportedURL table the admin sees, in full, on the Blacklist Database
    page) - so a user can see only what they personally reported."""
    return (
        db.query(ReportedURL)
        .filter(ReportedURL.user_id == user.id)
        .order_by(desc(ReportedURL.created_at))
        .all()
    )

# ---------------------------------------------------------------------------
# Websites the user blocked from the extension ("Block URL")
# ---------------------------------------------------------------------------
@router.get("/api/my-blocked-urls")
def my_blocked_urls(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    rows = (
        db.query(UserBlockedURL)
        .filter(UserBlockedURL.user_id == user.id)
        .order_by(desc(UserBlockedURL.created_at))
        .all()
    )
    return [
        {
            "id": r.id, "url": r.url, "hostname": r.hostname,
            "attack_type": r.attack_type, "created_at": r.created_at,
        }
        for r in rows
    ]


@router.delete("/api/my-blocked-urls/{block_id}", status_code=status.HTTP_204_NO_CONTENT)
def unblock_url(
    block_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    row = (
        db.query(UserBlockedURL)
        .filter(UserBlockedURL.id == block_id, UserBlockedURL.user_id == user.id)
        .first()
    )
    if not row:
        raise HTTPException(404, "Blocked URL not found")
    db.delete(row)
    db.commit()


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
@router.get("/api/profile", response_model=UserOut)
def get_profile(user: User = Depends(current_user)):
    return user


@router.patch("/api/profile", response_model=UserOut)
def update_profile(
    payload: ProfileUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
    if payload.email is not None and payload.email.lower() != user.email:
        clash = db.query(User).filter(User.email == payload.email.lower()).first()
        if clash:
            raise HTTPException(409, "Another account already uses that email")
        user.email = payload.email.lower()
    db.commit()
    db.refresh(user)
    return user


@router.post("/api/profile/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: PasswordChange,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    user.password_hash = hash_password(payload.new_password)
    db.commit()
