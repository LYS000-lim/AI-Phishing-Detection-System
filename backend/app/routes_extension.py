from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .allowlist import is_trusted, matched_domain
from .auth import current_user, try_current_user
from .database import get_db
from .features import extract_features, feature_vector
from .ml_state import MODEL, classify_vec, model_info
from .phishing_type import detect_phishing_type
from .models import BlockedURL, Detection, ExtensionReport, User, UserBlockedURL
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
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(try_current_user),
):
    """
    Chrome Extension scan - anonymous by default.

    If the extension has a signed-in website account (Authorization: Bearer
    <token> from the Settings page sign-in), the scan is ALSO logged to the
    same Detection table website scans use (tagged source="extension"), so
    it shows up in that user's Browser Extension Detection History. Without
    a valid token, behaviour is identical to before: real-time prediction
    only, nothing saved.
    """

    url = payload.get("url")

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL is required",
        )

    ip = request.client.host if request.client else None

    # Reputation-list bypass: well-known trusted domains skip ML
    # classification entirely, matching routes_user.py's _predict_and_log.
    if is_trusted(url):
        if user is not None:
            db.add(Detection(
                user_id=user.id, url=url, prediction="legitimate", label=0,
                confidence=1.0, phishing_probability=0.0, risk_level="Low",
                model_used="TrustedAllowlist", ip_address=ip, source="extension",
            ))
            db.commit()
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

        features = extract_features(url)

        # Same tuned thresholds + missing-HTTPS softening as the website
        # scanner (explanations.classify).
        verdict = classify_vec(vec, features, url)
        label = verdict["label"]
        phishing_probability = verdict["p_phish"]
        confidence = verdict["confidence"]
        prediction = verdict["prediction"]
        risk = verdict["risk"]
        uncertain_reason = verdict["uncertain_reason"]

        attack_type = None

        if prediction == "phishing":
            attack_type = detect_phishing_type(
                url,
                features,
            )

        if user is not None:
            db.add(Detection(
                user_id=user.id, url=url, prediction=prediction, label=label,
                confidence=round(confidence, 4),
                phishing_probability=round(phishing_probability, 4),
                risk_level=risk, model_used=model_info()["name"],
                attack_type=attack_type["category"] if attack_type else None,
                ip_address=ip, source="extension",
            ))
            db.commit()

        return {
            "url": url,
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "phishing_probability": round(
                phishing_probability,
                4,
            ),
            "legitimate_probability": round(
                1 - phishing_probability,
                4,
            ),
            "risk_level": risk,
            "model_used": model_info()["name"],
            "trusted_domain": False,
            "uncertain_reason": uncertain_reason,
            "legit_reason": verdict["legit_reason"],
            "escalated_by": verdict["escalated_by"],
            "brand": verdict["brand"],
            "reputation": verdict["reputation"],
            "attack_type": attack_type,
        }


    except HTTPException:
        raise
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
    user: Optional[User] = Depends(try_current_user),
):
    """
    Blacklist lookup used by the extension before/instead of running the
    ML model, so admin-confirmed phishing domains are blocked immediately
    on every future visit. When the extension is signed in, the user's own
    "Block URL" list (saved to their account) is checked too.
    """

    domain = _hostname(url)

    if not domain:
        return {"blocked": False}

    if user is not None:
        own = (
            db.query(UserBlockedURL)
            .filter(UserBlockedURL.user_id == user.id, UserBlockedURL.hostname == domain)
            .first()
        )
        if own:
            return {
                "blocked": True,
                "by_user": True,
                "domain": domain,
                "risk_level": "High",
                "reason": "You previously chose to block this website.",
            }

    entry = (
        db.query(BlockedURL)
        .filter(BlockedURL.domain == domain)
        .first()
    )

    if not entry:
        # user_checked tells the extension the account block list was really
        # consulted (valid token), so it may drop a stale local copy.
        return {"blocked": False, "user_checked": user is not None}

    return {
        "blocked": True,
        "domain": entry.domain,
        "risk_level": entry.risk_level,
        "reason": entry.reason,
    }


# ==========================================================
# User "Block URL" list (signed-in extension only)
# ==========================================================

def _save_user_block(db: Session, user: User, url: str, attack_type: Optional[str],
                     blocked_at: Optional[datetime] = None) -> bool:
    host = _hostname(url)
    if not host:
        return False
    exists = (
        db.query(UserBlockedURL)
        .filter(UserBlockedURL.user_id == user.id, UserBlockedURL.hostname == host)
        .first()
    )
    if exists:
        return False
    row = UserBlockedURL(user_id=user.id, url=url, hostname=host, attack_type=attack_type)
    if blocked_at is not None:
        row.created_at = blocked_at
    db.add(row)
    return True


@router.post("/user-blocks")
def add_user_block(
    payload: dict = Body(...),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Save one "Block URL" click from the warning page to the account."""
    url = (payload.get("url") or "").strip()
    if not url:
        raise HTTPException(400, "URL is required")
    added = _save_user_block(db, user, url, payload.get("attack_type"))
    db.commit()
    return {"saved": added}


@router.post("/user-blocks/sync")
def sync_user_blocks(
    payload: List[dict] = Body(...),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Upload blocks made while the extension was signed out, so the
    account list is complete after the user signs in."""
    added = 0
    for entry in payload[:500]:
        url = (entry.get("url") or "").strip()
        # "time" = when the block happened (ms since epoch), so the account
        # list shows the real block date rather than the sync date.
        blocked_at = None
        if isinstance(entry.get("time"), (int, float)):
            blocked_at = datetime.fromtimestamp(entry["time"] / 1000, timezone.utc).replace(tzinfo=None)
        if url and _save_user_block(db, user, url, None, blocked_at):
            added += 1
            db.flush()
    db.commit()
    return {"added": added}


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
    user: Optional[User] = Depends(try_current_user),
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

        user_id=user.id if user else None,
    )


    db.add(report)

    db.commit()

    db.refresh(report)


    return report