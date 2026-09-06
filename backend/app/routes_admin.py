import os
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import Integer, desc, func
from sqlalchemy.orm import Session

from .auth import hash_password, require_admin
from .database import get_db
from .features import FEATURE_ORDER
from .ml_state import (
    DT_METRICS, MODEL_LABEL, RF_METRICS,
    global_shap_importance, model_info,
)
from .models import Detection, ReportedURL, User
from .schemas import (
    AdminCreateUser, AdminUserUpdate, DetectionWithUser, UserOut,
)

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@router.get("/dashboard")
def dashboard(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    total_users = db.query(User).count()
    total_scans = db.query(Detection).count()
    total_phish = db.query(Detection).filter(Detection.label == 1).count()
    total_legit = total_scans - total_phish

    # Detection trend for the last 14 days
    # Stored timestamps are naive UTC (see models.py), so compare against
    # a naive UTC value here for portability across SQLite dialects.
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=14)
    trend_rows = (
        db.query(
            func.date(Detection.created_at).label("day"),
            func.sum((Detection.label == 1).cast(Integer)).label("phishing"),
            func.sum((Detection.label == 0).cast(Integer)).label("legitimate"),
        )
        .filter(Detection.created_at >= since)
        .group_by("day").order_by("day").all()
    )
    trend = [
        {"day": r.day, "phishing": int(r.phishing or 0),
         "legitimate": int(r.legitimate or 0)}
        for r in trend_rows
    ]

    # User activity - top 10 scanners
    activity_rows = (
        db.query(User.full_name, User.email, func.count(Detection.id).label("scans"))
        .join(Detection, Detection.user_id == User.id)
        .group_by(User.id).order_by(desc("scans")).limit(10).all()
    )
    activity = [
        {"user": r.full_name, "email": r.email, "scans": int(r.scans)}
        for r in activity_rows
    ]

    return {
        "totals": {
            "users": total_users,
            "scans": total_scans,
            "phishing": total_phish,
            "legitimate": total_legit,
        },
        "phishing_distribution": {
            "phishing": total_phish, "legitimate": total_legit,
        },
        "trend_14d": trend,
        "top_users": activity,
    }


# ---------------------------------------------------------------------------
# Detection logs (all users)
# ---------------------------------------------------------------------------
@router.get("/detections")
def all_detections(
    page: int = 1,
    page_size: int = 20,
    q: Optional[str] = None,
    result: Optional[str] = None,          # "phishing" | "legitimate"
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    query = db.query(Detection, User).join(User, User.id == Detection.user_id)
    if q:
        query = query.filter(
            (Detection.url.ilike(f"%{q}%")) | (User.email.ilike(f"%{q}%")),
        )
    if result in ("phishing", "legitimate"):
        query = query.filter(Detection.prediction == result)
    total = query.count()

    rows = (
        query
        .order_by(desc(Detection.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "items": [
            DetectionWithUser(
                id=d.id,
                url=d.url,
                prediction=d.prediction,
                label=d.label,
                confidence=d.confidence,
                phishing_probability=d.phishing_probability,
                risk_level=d.risk_level,
                model_used=d.model_used,
                created_at=d.created_at,
                ip_address=d.ip_address,
                user_email=u.email,
                user_name=u.full_name,
            )
            for d, u in rows
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.delete("/detections/{detection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_detection(
    detection_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    row = db.query(Detection).filter(Detection.id == detection_id).first()
    if not row:
        raise HTTPException(404, "Detection not found")
    db.delete(row)
    db.commit()


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------
@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: AdminCreateUser,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """
    Admin-only manual account creation.

    Lets an admin create either a User or an Admin account without going
    through public registration. Used from the User Management page's
    "Add New User" modal.
    """
    exists = db.query(User).filter(User.email == payload.email.lower()).first()
    if exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email already exists",
        )
    user = User(
        full_name=payload.full_name.strip(),
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/users", response_model=List[UserOut])
def list_users(
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    query = db.query(User)
    if q:
        query = query.filter(
            (User.email.ilike(f"%{q}%")) | (User.full_name.ilike(f"%{q}%")),
        )
    return query.order_by(User.created_at.desc()).all()


@router.patch("/users/{user_id}", response_model=UserOut)
def edit_user(
    user_id: int,
    payload: AdminUserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    row = db.query(User).filter(User.id == user_id).first()
    if not row:
        raise HTTPException(404, "User not found")

    if payload.full_name is not None:
        row.full_name = payload.full_name.strip()
    if payload.email is not None:
        clash = (
            db.query(User)
            .filter(User.email == payload.email.lower(), User.id != user_id)
            .first()
        )
        if clash:
            raise HTTPException(409, "Another account already uses that email")
        row.email = payload.email.lower()
    if payload.role is not None:
        row.role = payload.role
    if payload.is_active is not None:
        # Guard: don't let an admin deactivate the last remaining active admin
        if (row.role == "admin" and payload.is_active is False):
            remaining = (
                db.query(User)
                .filter(User.role == "admin", User.is_active.is_(True),
                        User.id != user_id)
                .count()
            )
            if remaining == 0:
                raise HTTPException(400, "Cannot deactivate the last active admin")
        row.is_active = payload.is_active

    db.commit()
    db.refresh(row)
    return row


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if user_id == admin.id:
        raise HTTPException(400, "You cannot delete your own account")
    row = db.query(User).filter(User.id == user_id).first()
    if not row:
        raise HTTPException(404, "User not found")
    if row.role == "admin":
        remaining = (
            db.query(User)
            .filter(User.role == "admin", User.id != user_id).count()
        )
        if remaining == 0:
            raise HTTPException(400, "Cannot delete the last admin")
    db.delete(row)
    db.commit()


# ---------------------------------------------------------------------------
# Model analytics (Interface 10)
# ---------------------------------------------------------------------------
@router.get("/analytics")
def analytics(_: User = Depends(require_admin)):
    """Metrics for both models + which one is deployed."""
    return {
        "deployed": model_info(),
        "label_convention": {"0": "Legitimate", "1": "Phishing"},
        "positive_class": "Phishing",
        "models": {
            "decision_tree": DT_METRICS,
            "random_forest": RF_METRICS,
        },
        "winner": MODEL_LABEL,
    }


@router.get("/analytics/global-shap")
def global_shap(top: int = 15, _: User = Depends(require_admin)):
    """Mean-|SHAP| per URL feature, computed on a background sample."""
    values = global_shap_importance()
    pairs = sorted(
        zip(FEATURE_ORDER, values), key=lambda p: p[1], reverse=True,
    )[:top]
    return {
        "note": "Mean absolute SHAP value across a random background sample "
                "of URLs. Higher = feature more influential globally.",
        "features": [
            {"name": n, "mean_abs_shap": round(float(v), 5)} for n, v in pairs
        ],
    }

# ---------------------------------------------------------------------------
# Blacklist Database
# ---------------------------------------------------------------------------

@router.get("/reported-urls")
def reported_urls(
    page: int = 1,
    page_size: int = 20,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    query = db.query(ReportedURL)

    if q:
        query = query.filter(
            ReportedURL.url.ilike(f"%{q}%")
        )

    total = query.count()

    rows = (
        query
        .order_by(desc(ReportedURL.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "items": [
            {
                "id": r.id,
                "url": r.url,
                "attack_type": r.attack_type,
                "detection_reason": r.detection_reason,
                "created_at": r.created_at,
            }
            for r in rows
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }

# ---------------------------------------------------------------------------
# Blacklist Report Export
# ---------------------------------------------------------------------------

@router.get("/reported-urls/export")
def export_blacklist_pdf(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    reports = (
        db.query(ReportedURL)
        .order_by(desc(ReportedURL.created_at))
        .all()
    )

    file_path = "PhishGuard_Blacklist_Report.pdf"

    doc = SimpleDocTemplate(file_path)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "PhishGuard AI - Blacklist Database Report",
            styles["Title"]
        )
    )

    data = [
        [
            "No",
            "URL",
            "Attack Type",
            "Detection Reason",
            "Date"
        ]
    ]

    for index, row in enumerate(reports, start=1):
        data.append(
            [
                str(index),
                row.url,
                row.attack_type or "-",
                row.detection_reason,
                row.created_at.strftime("%Y-%m-%d")
            ]
        )

    table = Table(data, repeatRows=1)

    table.setStyle(
        TableStyle([
            ("GRID", (0,0), (-1,-1), 0.5, None),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
        ])
    )

    content.append(table)

    doc.build(content)

    return FileResponse(
        file_path,
        media_type="application/pdf",
        filename="PhishGuard_Blacklist_Report.pdf"
    )