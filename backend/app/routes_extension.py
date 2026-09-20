from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .allowlist import is_trusted, matched_domain
from .database import get_db
from .features import extract_features, feature_vector
from .explanations import risk_level
from .ml_state import MODEL, model_info
from .phishing_type import detect_phishing_type
from .models import BlockedURL, ExtensionReport
from .schemas import ExtensionReportCreate, ExtensionReportOut


router = APIRouter(
    prefix="/api/extension",
    tags=["extension"],
)


# ==========================================================
# Extension URL Scan
# ==========================================================

@router.post("/scan")
def extension_scan(
    payload: dict,
):
    """
    Anonymous Chrome Extension scan.

    Important:
    - Does NOT save into Detection table.
    - Only performs real-time prediction.
    """

    url = payload.get("url")

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL is required",
        )

    # Reputation-list bypass: well-known trusted domains skip ML
    # classification entirely, matching routes_user.py's _predict_and_log.
    if is_trusted(url):
        return {
            "url": url,
            "prediction": "legitimate",
            "confidence": 1.0,
            "phishing_probability": 0.0,
            "legitimate_probability": 1.0,
            "risk_level": "Low",
            "model_used": "TrustedAllowlist",
            "trusted_domain": True,
            "matched_domain": matched_domain(url),
            "attack_type": None,
        }

    if MODEL is None:
        raise HTTPException(
            status_code=503,
            detail="Model unavailable",
        )

    try:
        vec = feature_vector(url)

        label = int(MODEL.predict(vec)[0])

        probability = MODEL.predict_proba(vec)[0]

        phishing_probability = float(probability[1])

        confidence = float(max(probability))

        prediction = (
            "phishing"
            if label == 1
            else "legitimate"
        )

        risk = risk_level(
            phishing_probability
        )

        features = extract_features(url)

        attack_type = None

        if prediction == "phishing":
            attack_type = detect_phishing_type(
                url,
                features,
            )

        return {
            "url": url,
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "phishing_probability": round(
                phishing_probability,
                4,
            ),
            "legitimate_probability": round(
                float(probability[0]),
                4,
            ),
            "risk_level": risk,
            "model_used": model_info()["name"],
            "trusted_domain": False,
            "attack_type": attack_type,
        }


    except Exception as exc:

        raise HTTPException(
            status_code=422,
            detail=f"Could not process URL: {exc}",
        )


# ==========================================================
# Blacklist Check
# ==========================================================

def _hostname(url: str) -> str:
    raw = url.strip()
    if not raw.lower().startswith(("http://", "https://")):
        raw = "http://" + raw
    return (urlparse(raw).hostname or "").lower()


@router.get("/check-blacklist")
def check_blacklist(
    url: str,
    db: Session = Depends(get_db),
):
    """
    Anonymous blacklist lookup used by the extension before/instead of
    running the ML model, so admin-confirmed phishing domains are blocked
    immediately on every future visit.
    """

    domain = _hostname(url)

    if not domain:
        return {"blocked": False}

    entry = (
        db.query(BlockedURL)
        .filter(BlockedURL.domain == domain)
        .first()
    )

    if not entry:
        return {"blocked": False}

    return {
        "blocked": True,
        "domain": entry.domain,
        "risk_level": entry.risk_level,
        "reason": entry.reason,
    }


# ==========================================================
# Anonymous Extension Report
# ==========================================================

@router.post(
    "/report",
    response_model=ExtensionReportOut,
)
def extension_report(
    payload: ExtensionReportCreate,
    request: Request,
    db: Session = Depends(get_db),
):

    existing = (
        db.query(ExtensionReport)
        .filter(
            ExtensionReport.url == payload.url
        )
        .first()
    )


    if existing:

        raise HTTPException(
            status_code=409,
            detail="URL already reported",
        )


    report = ExtensionReport(

        url=payload.url,

        attack_type=payload.attack_type,

        detection_reason=payload.detection_reason,

        browser_info=payload.browser_info,

        ip_address=(
            request.client.host
            if request.client
            else None
        ),

        status="pending",
    )


    db.add(report)

    db.commit()

    db.refresh(report)


    return report