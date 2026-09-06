from typing import List, Optional

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from .auth import current_user, hash_password, verify_password
from .allowlist import is_trusted, matched_domain
from .database import get_db
from .explanations import plain_text_explanation, risk_level
from .features import FEATURE_ORDER, extract_features, feature_vector
from .ml_state import get_lime_explainer, get_shap_explainer, model_info, MODEL
from .models import Detection, ReportedURL, User
from .schemas import (
    BatchRequest, DetectionOut, PasswordChange, ProfileUpdate,
    ReportURLRequest, ReportedURLOut,
    URLRequest, UserOut,
)

from .features import FEATURE_ORDER, extract_features, feature_vector
from .ml_state import get_lime_explainer, get_shap_explainer, model_info, MODEL
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
) -> dict:
    # Reputation-list bypass: well-known trusted domains skip ML
    # classification entirely. Prevents false positives on obviously
    # legitimate URLs (chatgpt.com, google.com, github.com, ...) which
    # the URL-only model may not have seen in training.
    if is_trusted(url):
        domain = matched_domain(url)
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
            "matched_domain": domain,
            "features": extract_features(url),
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
    label = int(MODEL.predict(vec)[0])                 # 0=Legit, 1=Phish
    proba = MODEL.predict_proba(vec)[0]
    p_phish = float(proba[1])
    confidence = float(max(proba))
    prediction = "phishing" if label == 1 else "legitimate"
    risk = risk_level(p_phish)

    features = extract_features(url)

    attack_type = None

    if prediction == "phishing":
        attack_type = detect_phishing_type(
            url,
            features
        )

    record = Detection(
        user_id=user.id,
        url=url,
        prediction=prediction,
        label=label,
        confidence=round(confidence, 4),
        phishing_probability=round(p_phish, 4),
        risk_level=risk,
        model_used=model_info()["name"],
        ip_address=ip,
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
        "legitimate_probability": round(float(proba[0]), 4),
        "risk_level": risk,
        "model_used": model_info()["name"],
        "features": extract_features(url),
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
    # Allowlist short-circuit: mirror what /api/scan does so the frontend
    # gets a consistent explanation object without spurious SHAP values
    # for a URL that was never actually classified by the model.
    if is_trusted(req.url):
        domain = matched_domain(req.url)
        return {
            "url": req.url,
            "prediction": "legitimate",
            "risk_level": "Low",
            "confidence": 1.0,
            "phishing_probability": 0.0,
            "model_used": "TrustedAllowlist",
            "plain_text": (
                f"This URL was recognised as belonging to '{domain}', a "
                f"well-known trusted domain, and was classified as "
                f"LEGITIMATE without running through the ML model. Real "
                f"phishing detection systems combine ML with reputation "
                f"lists like this one to avoid false positives on popular "
                f"legitimate sites."
            ),
            "matched_domain": domain,
            "shap": {
                "note": "Trusted-allowlist bypass - SHAP not computed.",
                "top_features": [],
            },
            "lime": {
                "note": "Trusted-allowlist bypass - LIME not computed.",
                "top_rules": [],
            },
        }

    try:
        vec = feature_vector(req.url)
    except Exception as exc:
        raise HTTPException(422, f"Could not process URL: {exc}")

    label = int(MODEL.predict(vec)[0])
    proba = MODEL.predict_proba(vec)[0]
    p_phish = float(proba[1])
    prediction = "phishing" if label == 1 else "legitimate"
    risk = risk_level(p_phish)

    # SHAP contributions for class 1 (phishing)
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

    # LIME local rules
    lime_exp = get_lime_explainer()
    explanation = lime_exp.explain_instance(
        vec[0], MODEL.predict_proba, num_features=10, labels=[1],
    )
    lime_out = [
        {"rule": rule, "weight": round(float(w), 5)}
        for rule, w in explanation.as_list(label=1)
    ]

    plain = plain_text_explanation(prediction, risk, shap_out)

    return {
        "url": req.url,
        "prediction": prediction,
        "risk_level": risk,
        "confidence": round(float(max(proba)), 4),
        "phishing_probability": round(p_phish, 4),
        "model_used": model_info()["name"],
        "plain_text": plain,
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
@router.get("/api/detections", response_model=List[DetectionOut])
def my_detections(
    limit: int = 100,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = db.query(Detection).filter(Detection.user_id == user.id)
    if q:
        query = query.filter(Detection.url.ilike(f"%{q}%"))
    return query.order_by(desc(Detection.created_at)).limit(limit).all()


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

    return {
        "totals": {"total": total, "phishing": phish, "legitimate": legit},
        "feature_distribution": dist,
        "recent": [DetectionOut.model_validate(r).model_dump(mode="json")
                   for r in recent],
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
