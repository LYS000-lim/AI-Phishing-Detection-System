import csv
import io
from collections import Counter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from datetime import date, datetime, time, timedelta, timezone
from typing import List, Optional
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import Integer, desc, func
from sqlalchemy.orm import Session, joinedload

from .allowlist import is_trusted
from .auth import hash_password, require_admin
from .database import get_db
from .features import FEATURE_ORDER
from .ml_state import (
    DT_METRICS, MODEL_LABEL, RF_METRICS,
    global_lime_importance, global_shap_importance, model_info,
)
from .models import BlockedURL, Detection, ReportedURL, ExtensionReport, User, UserBlockedURL
from .phishing_type import detect_brand
from .reputation import domain_reputation
from .routes_user import (
    _feature_distribution, _predict_and_log, _resolve_window, _source_distribution,
)
from .schemas import (
    AdminCreateUser, AdminUserUpdate, DetectionWithUser, URLRequest, UserOut,
)

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@router.get("/dashboard")
def dashboard(
    days: int = 14,
    date_from: Optional[str] = None,       # "YYYY-MM-DD", overrides `days` with `date_to`
    date_to: Optional[str] = None,         # "YYYY-MM-DD"
    source: Optional[str] = None,          # "website" | "extension"
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    # User activity - top 10 scanners (lifetime; not part of the date/source
    # filter below since "who scans the most overall" is a different
    # question from "what happened in this period").
    activity_rows = (
        db.query(User.full_name, User.email, func.count(Detection.id).label("scans"))
        .join(Detection, Detection.user_id == User.id)
        .group_by(User.id).order_by(desc("scans")).limit(10).all()
    )
    activity = [
        {"user": r.full_name, "email": r.email, "scans": int(r.scans)}
        for r in activity_rows
    ]

    deployed_metrics = RF_METRICS if MODEL_LABEL == "RandomForest" else DT_METRICS

    # ------------------------------------------------------------------
    # Everything below - System Overview, Threat Intelligence, and the
    # interactive visuals (Threat Trend, Detection Result Overview, Important
    # URL Characteristics, Attack Category Analysis, Detection Source
    # Distribution) - is scoped to the same days/date_from/date_to/source
    # filters, so the whole dashboard (except the lifetime User Activity
    # table above) reflects one selected period. Same shape as the User
    # Dashboard's /api/detections/dashboard-visuals so both pages share one
    # rendering component.
    # ------------------------------------------------------------------
    v_since, v_until = _resolve_window(days, date_from, date_to)
    v_query = db.query(Detection).filter(
        Detection.created_at >= v_since, Detection.created_at < v_until,
    )
    if source in ("website", "extension"):
        v_query = v_query.filter(Detection.source == source)
    else:  # "All sources" excludes the admin's own test scans
        v_query = v_query.filter(Detection.source.in_(("website", "extension")))
    v_rows = v_query.all()

    v_phishing = sum(1 for r in v_rows if r.label == 1)
    v_legitimate = len(v_rows) - v_phishing
    v_active_users = len({r.user_id for r in v_rows if r.user_id is not None})
    v_extension_detections = sum(1 for r in v_rows if r.source == "extension")
    source_distribution = _source_distribution([r.source for r in v_rows])

    blocked_urls_count = (
        db.query(BlockedURL)
        .filter(BlockedURL.created_at >= v_since, BlockedURL.created_at < v_until)
        .count()
    )
    pending_reports_count = (
        db.query(ExtensionReport)
        .filter(
            ExtensionReport.status == "pending",
            ExtensionReport.created_at >= v_since,
            ExtensionReport.created_at < v_until,
        )
        .count()
    )

    attack_category_frequency = [
        {"category": category, "count": count}
        for category, count in Counter(
            r.attack_type for r in v_rows if r.attack_type
        ).most_common()
    ]
    top_attack_type = attack_category_frequency[0]["category"] if attack_category_frequency else None

    # Most targeted brand - derived from phishing URLs' hostnames rather than
    # a stored column, since brand impersonation is a lightweight lookup
    # (see phishing_type.detect_brand) not persisted on the Detection row.
    brand_counts = Counter(
        b for r in v_rows if r.label == 1 and (b := detect_brand(r.url))
    )
    most_targeted_brand = brand_counts.most_common(1)[0][0] if brand_counts else None

    v_trend_map = {}
    for r in v_rows:
        day = r.created_at.date().isoformat()
        bucket = v_trend_map.setdefault(day, {"phishing": 0, "legitimate": 0})
        bucket["phishing" if r.label == 1 else "legitimate"] += 1
    v_trend = [{"day": day, **counts} for day, counts in sorted(v_trend_map.items())]

    visuals = {
        "date_from": v_since.date().isoformat(),
        "date_to": (v_until - timedelta(days=1)).date().isoformat(),
        "trend": v_trend,
        "result_counts": {"phishing": v_phishing, "legitimate": v_legitimate},
        "feature_distribution": _feature_distribution([r.url for r in v_rows]),
        "attack_category_frequency": attack_category_frequency,
        "source_distribution": source_distribution,
    }

    return {
        "totals": {
            "users": v_active_users,
            "scans": len(v_rows),
            "phishing": v_phishing,
            "legitimate": v_legitimate,
            "extension_detections": v_extension_detections,
        },
        "top_users": activity,
        "blocked_urls_count": blocked_urls_count,
        "pending_reports_count": pending_reports_count,
        "most_common_attack_type": top_attack_type,
        "most_targeted_brand": most_targeted_brand,
        "detection_accuracy": deployed_metrics.get("accuracy"),
        "deployed_model": MODEL_LABEL,
        "visuals": visuals,
    }


# ---------------------------------------------------------------------------
# Browser Extension Monitoring (admin-wide, source="extension" only)
# ---------------------------------------------------------------------------
@router.get("/extension-monitoring")
def extension_monitoring(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    base = db.query(Detection).filter(Detection.source == "extension")
    start, end = _date_range_bounds(date_from, date_to)
    if start:
        base = base.filter(Detection.created_at >= start)
    if end:
        base = base.filter(Detection.created_at <= end)

    total_extension_users = base.with_entities(Detection.user_id).distinct().count()
    extension_detection_count = base.count()
    threats_found = base.filter(Detection.label == 1).count()

    # Intentionally no trend/attack-category charts here - those already
    # live on the Admin Dashboard (filterable by source=extension) and on
    # this page they'd just be an unfiltered duplicate. This page stays
    # focused on extension-specific activity: who's using it, how much,
    # and the raw records.
    return {
        "totals": {
            "extension_users": total_extension_users,
            "extension_detections": extension_detection_count,
            "threats_found": threats_found,
        },
    }


# ---------------------------------------------------------------------------
# Admin URL Scanner (Interface: admin manually scanning, tagged source="admin")
# ---------------------------------------------------------------------------
@router.post("/scan")
def admin_scan(
    req: URLRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    try:
        return _predict_and_log(
            req.url, admin, db,
            ip=request.client.host if request.client else None,
            source="admin",
        )
    except Exception as exc:
        raise HTTPException(422, f"Could not process URL: {exc}")


# ---------------------------------------------------------------------------
# Detection logs (all users)
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


def _filtered_detections_query(
    db: Session,
    q: Optional[str] = None,
    result: Optional[str] = None,
    risk: Optional[str] = None,
    attack_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    source: Optional[str] = None,
    own_user_id: Optional[int] = None,
):
    """Shared filter-building logic for the detection log listing, its
    analytics summary, and its CSV/PDF export - so all three always agree
    on what "the current filters" means. own_user_id: the "My Scans" tab -
    only that admin's own scans, from every source including the Admin
    Scanner."""
    query = db.query(Detection, User).join(User, User.id == Detection.user_id)
    if q:
        query = query.filter(
            (Detection.url.ilike(f"%{q}%")) | (User.email.ilike(f"%{q}%")),
        )
    if result in ("phishing", "legitimate", "uncertain"):
        query = query.filter(Detection.prediction == result)
    if risk in ("Low", "Medium", "High"):
        query = query.filter(Detection.risk_level == risk)
    if attack_type:
        query = query.filter(Detection.attack_type == attack_type)
    # Every scan is listed, including admins' own Admin Scanner scans
    # (source="admin"); the Admin Dashboard statistics still leave those out.
    if own_user_id is not None:
        query = query.filter(Detection.user_id == own_user_id)
    if source in ("website", "extension", "admin"):
        query = query.filter(Detection.source == source)

    start, end = _date_range_bounds(date_from, date_to)
    if start:
        query = query.filter(Detection.created_at >= start)
    if end:
        query = query.filter(Detection.created_at <= end)
    return query


def _detection_analytics_summary(rows: list) -> dict:
    """rows: list of (Detection, User) tuples already matching the current
    filters. Powers the Detection Logs 'Analysis Summary' panel."""
    total = len(rows)
    phishing = sum(1 for d, _ in rows if d.label == 1)
    legitimate = total - phishing
    detection_rate = round(phishing / total * 100, 1) if total else 0.0
    avg_confidence = (
        round(sum(d.confidence for d, _ in rows) / total * 100, 1) if total else 0.0
    )
    attack_counts = Counter(d.attack_type for d, _ in rows if d.attack_type)
    most_common_attack_type = attack_counts.most_common(1)[0][0] if attack_counts else None
    return {
        "total_detections": total,
        "phishing_count": phishing,
        "legitimate_count": legitimate,
        "detection_rate_pct": detection_rate,
        "most_common_attack_type": most_common_attack_type,
        "average_confidence_pct": avg_confidence,
    }


@router.get("/detections")
def all_detections(
    page: int = 1,
    page_size: int = 20,
    q: Optional[str] = None,
    result: Optional[str] = None,          # "phishing" | "legitimate"
    risk: Optional[str] = None,            # "Low" | "Medium" | "High"
    attack_type: Optional[str] = None,
    date_from: Optional[str] = None,       # "YYYY-MM-DD"
    date_to: Optional[str] = None,
    source: Optional[str] = None,          # "website" | "extension" (| "admin" with mine)
    mine: bool = False,                    # "My Scans" tab: this admin's own scans
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    query = _filtered_detections_query(
        db, q, result, risk, attack_type, date_from, date_to, source,
        own_user_id=admin.id if mine else None,
    )

    total = query.count()
    all_matching = query.order_by(desc(Detection.created_at)).all()

    rows = all_matching[(page - 1) * page_size: (page - 1) * page_size + page_size]

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
                attack_type=d.attack_type,
                created_at=d.created_at,
                ip_address=d.ip_address,
                source=d.source,
                user_email=u.email,
                user_name=u.full_name,
            )
            for d, u in rows
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
        "summary": _detection_analytics_summary(all_matching),
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


_SOURCE_LABELS = {
    "website": "Website Scanner",
    "extension": "Chrome Extension",
    "admin": "Admin Scanner",
}


@router.get("/detections/export")
def export_detections(
    format: str = "csv",                   # "csv" | "pdf"
    q: Optional[str] = None,
    result: Optional[str] = None,
    risk: Optional[str] = None,
    attack_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    source: Optional[str] = None,
    mine: bool = False,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Download the currently-filtered Detection Logs as CSV or PDF."""
    if format not in ("csv", "pdf"):
        raise HTTPException(400, "format must be 'csv' or 'pdf'")

    query = _filtered_detections_query(
        db, q, result, risk, attack_type, date_from, date_to, source,
        own_user_id=admin.id if mine else None,
    )
    rows = query.order_by(desc(Detection.created_at)).all()

    filename_base = f"{datetime.now(timezone.utc):%B}_Detection_Report"

    headers = ["URL", "Result", "Risk", "Attack Type", "Detection Source", "Date", "Confidence"]

    def _row_values(d: Detection, u: User):
        return [
            d.url,
            d.prediction,
            d.risk_level,
            d.attack_type or "-",
            _SOURCE_LABELS.get(d.source, d.source),
            d.created_at.strftime("%Y-%m-%d %H:%M"),
            f"{d.confidence * 100:.1f}%",
        ]

    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(headers)
        for d, u in rows:
            writer.writerow(_row_values(d, u))
        buf.seek(0)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.csv"'},
        )

    return _pdf_table_response(
        "PhishGuard AI - Detection Report", headers,
        [_row_values(d, u) for d, u in rows],
        col_widths_mm=[100, 20, 16, 38, 32, 28, 20], url_cols={0},
        filename=f"{filename_base}.pdf",
    )


def _pdf_table_response(title, headers, rows, col_widths_mm, url_cols, filename):
    """One-table PDF (A4 landscape) built in memory. Every cell is a wrapped
    Paragraph inside a fixed column width, and URL columns may break at any
    character, so one long URL or detection reason can no longer stretch the
    table off the page (it previously did, leaving the PDF unreadable)."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), title=title,
                            leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=12 * mm)
    styles = getSampleStyleSheet()
    text = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=7.5, leading=9)
    url = ParagraphStyle("url", parent=text, wordWrap="CJK")
    head = ParagraphStyle("head", parent=text, fontName="Helvetica-Bold")
    data = [[Paragraph(escape(h), head) for h in headers]]
    data += [[Paragraph(escape(str(v)), url if i in url_cols else text) for i, v in enumerate(row)]
             for row in rows]
    table = Table(data, colWidths=[w * mm for w in col_widths_mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    doc.build([
        Paragraph(escape(title), styles["Title"]),
        Paragraph(f"{len(rows)} record(s), generated {datetime.now(timezone.utc):%d/%m/%Y %H:%M} UTC",
                  styles["Normal"]),
        table,
    ])
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


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


@router.get("/analytics/global-lime")
def global_lime(top: int = 15, _: User = Depends(require_admin)):
    """Mean-|LIME weight| per URL feature, averaged over local explanations
    on a background sample - an approximation of 'global' LIME behaviour."""
    values = global_lime_importance()
    pairs = sorted(
        zip(FEATURE_ORDER, values), key=lambda p: p[1], reverse=True,
    )[:top]
    return {
        "note": "Mean absolute LIME weight across a random background sample "
                "of URLs, averaged from per-URL local explanations. Higher = "
                "feature more often influential in individual predictions.",
        "features": [
            {"name": n, "mean_abs_weight": round(float(v), 5)} for n, v in pairs
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
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    sort: str = "newest",
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):

    user_reports = (
        db.query(ReportedURL)
        .options(joinedload(ReportedURL.user))
        .order_by(desc(ReportedURL.created_at))
        .all()
    )


    # Legacy "rejected" rows (from before rejection deleted the report)
    # are hidden - the admin already chose not to keep them.
    extension_reports = (
        db.query(ExtensionReport)
        .options(joinedload(ExtensionReport.user))
        .filter(ExtensionReport.status != "rejected")
        .order_by(desc(ExtensionReport.created_at))
        .all()
    )


    items = []


    # Existing registered user reports - each is tied to the user who
    # submitted it via the "Report URL" button on a scan result.
    for r in user_reports:

        items.append(
            {
                "id": r.id,
                "url": r.url,
                "attack_type": r.attack_type,
                "detection_reason": r.detection_reason,
                "source": "User Report",
                "status": r.status,
                "created_at": r.created_at,
                "reported_by_name": r.user.full_name if r.user else None,
                "reported_by_email": r.user.email if r.user else None,
            }
        )


    # Extension reports - attributed to the user when the extension was
    # signed in to a website account, otherwise anonymous.
    for r in extension_reports:

        items.append(
            {
                "id": r.id,
                "url": r.url,
                "attack_type": r.attack_type,
                "detection_reason": r.detection_reason,
                "source": "Chrome Extension",
                "status": r.status,
                "created_at": r.created_at,
                "reported_by_name": r.user.full_name if r.user else None,
                "reported_by_email": r.user.email if r.user else None,
            }
        )


    # How many reports (both sources) name the same hostname, so the admin
    # can sort by the most-reported sites and decide what to block globally.
    report_counts = Counter(_hostname(x["url"]) for x in items)
    blocked_domains = {d for (d,) in db.query(BlockedURL.domain).all()}
    for x in items:
        host = _hostname(x["url"])
        x["report_count"] = report_counts[host]
        x["globally_blocked"] = host in blocked_domains

    # Search + date filters
    if q:
        items = [
            x for x in items
            if q.lower() in x["url"].lower()
        ]
    start, end = _date_range_bounds(date_from, date_to)
    if start:
        items = [x for x in items if x["created_at"] >= start]
    if end:
        items = [x for x in items if x["created_at"] <= end]


    # Sort newest first

    items.sort(
        key=lambda x: x["created_at"],
        reverse=True,
    )
    # "Most reported": stable sort keeps newest first within a tie.
    if sort == "most_reported":
        items.sort(key=lambda x: x["report_count"], reverse=True)


    total = len(items)


    start = (page - 1) * page_size
    end = start + page_size

    # Blacklist Statistics — computed globally (not affected by the `q`
    # search filter above), reusing user_reports/extension_reports already
    # queried rather than issuing more queries.
    month_start = datetime.now(timezone.utc).replace(
        tzinfo=None, day=1, hour=0, minute=0, second=0, microsecond=0,
    )
    total_saved = db.query(BlockedURL).count()
    new_this_month = (
        db.query(BlockedURL)
        .filter(BlockedURL.created_at >= month_start)
        .count()
    )
    pending_reports = (
        db.query(ExtensionReport)
        .filter(ExtensionReport.status == "pending")
        .count()
    ) + (
        db.query(ReportedURL)
        .filter(ReportedURL.status == "pending")
        .count()
    )
    attack_counts = {}
    for r in (*user_reports, *extension_reports):
        if r.attack_type:
            attack_counts[r.attack_type] = attack_counts.get(r.attack_type, 0) + 1
    most_common_attack_category = (
        max(attack_counts, key=attack_counts.get) if attack_counts else None
    )

    return {
        "items": items[start:end],
        "page": page,
        "page_size": page_size,
        "total": total,
        "stats": {
            "total_saved": total_saved,
            "new_this_month": new_this_month,
            "pending_reports": pending_reports,
            "most_common_attack_category": most_common_attack_category,
        },
    }

# ---------------------------------------------------------------------------
# Extension Report Approval
# ---------------------------------------------------------------------------

def _hostname(url: str) -> str:
    raw = (url or "").strip()
    if not raw.lower().startswith(("http://", "https://")):
        raw = "http://" + raw
    try:
        return (urlparse(raw).hostname or "").lower()
    except ValueError:
        return ""


def _save_to_blocklist(db: Session, url: str, reason: Optional[str],
                       source: str, attack_type: Optional[str]) -> None:
    """"Save in Database": this is what actually makes the URL enforced as
    blocked going forward (see GET /api/extension/check-blacklist). Shared by
    extension reports and website (User Report) reports."""
    domain = _hostname(url)
    if not domain:
        return
    existing = (
        db.query(BlockedURL)
        .filter(BlockedURL.domain == domain)
        .first()
    )
    if not existing:
        db.add(
            BlockedURL(
                url=url,
                domain=domain,
                risk_level="High",
                reason=reason,
                source=source,
                attack_type=attack_type,
            )
        )

@router.post("/extension-reports/{report_id}/approve")
def approve_extension_report(
    report_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):

    report = (
        db.query(ExtensionReport)
        .filter(ExtensionReport.id == report_id)
        .first()
    )

    if not report:
        raise HTTPException(
            404,
            "Extension report not found"
        )


    report.status = "approved"

    report.reviewed_at = datetime.now(
        timezone.utc
    ).replace(tzinfo=None)

    _save_to_blocklist(db, report.url, report.detection_reason,
                       "Chrome Extension", report.attack_type)

    db.commit()
    db.refresh(report)


    return {
        "message": "Extension report approved",
        "id": report.id,
        "status": report.status,
    }

@router.post("/extension-reports/{report_id}/reject")
def reject_extension_report(
    report_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):

    report = (
        db.query(ExtensionReport)
        .filter(ExtensionReport.id == report_id)
        .first()
    )

    if not report:
        raise HTTPException(
            404,
            "Extension report not found"
        )


    # "Do Not Save in Database": the admin has dismissed the report, so it
    # is deleted outright rather than kept as a "rejected" row cluttering
    # the Blacklist table. This also lets the URL be reported again later.
    db.delete(report)
    db.commit()

    return {
        "message": "Extension report removed",
        "id": report_id,
        "status": "removed",
    }

# ---------------------------------------------------------------------------
# Website (User Report) Approval
# ---------------------------------------------------------------------------

@router.post("/user-reports/{report_id}/approve")
def approve_user_report(
    report_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    report = db.query(ReportedURL).filter(ReportedURL.id == report_id).first()
    if not report:
        raise HTTPException(404, "User report not found")

    report.status = "approved"
    report.reviewed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    _save_to_blocklist(db, report.url, report.detection_reason,
                       "PhishGuard Website", report.attack_type)

    db.commit()
    db.refresh(report)
    return {
        "message": "User report approved",
        "id": report.id,
        "status": report.status,
    }


@router.post("/user-reports/{report_id}/reject")
def reject_user_report(
    report_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    report = db.query(ReportedURL).filter(ReportedURL.id == report_id).first()
    if not report:
        raise HTTPException(404, "User report not found")

    # "Do Not Save in Database": same as extension reports - delete the row
    # so it leaves the Blacklist table and the URL can be reported again.
    db.delete(report)
    db.commit()
    return {
        "message": "User report removed",
        "id": report_id,
        "status": "removed",
    }

# ---------------------------------------------------------------------------
# Websites users blocked from the extension ("Block URL"), all accounts.
# The admin can review and unblock any user's block.
# ---------------------------------------------------------------------------

@router.get("/user-blocked-urls")
def all_user_blocked_urls(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    rows = (
        db.query(UserBlockedURL)
        .options(joinedload(UserBlockedURL.user))
        .order_by(desc(UserBlockedURL.created_at))
        .all()
    )
    return [
        {
            "id": r.id, "url": r.url, "hostname": r.hostname,
            "attack_type": r.attack_type, "risk_level": r.risk_level,
            "created_at": r.created_at,
            "user_name": r.user.full_name if r.user else None,
            "user_email": r.user.email if r.user else None,
        }
        for r in rows
    ]


@router.delete("/user-blocked-urls/{block_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_unblock_user_url(
    block_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    row = db.query(UserBlockedURL).filter(UserBlockedURL.id == block_id).first()
    if not row:
        raise HTTPException(404, "Blocked URL not found")
    db.delete(row)
    db.commit()

# ---------------------------------------------------------------------------
# Global Block: the admin pastes any URL (from the most-reported list or any
# other source) and blocks its hostname for all users. Same BlockedURL table
# the extension checks, so no extension change is needed. Only the admin can
# unblock.
# ---------------------------------------------------------------------------

@router.get("/global-blocks")
def global_blocks(
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    query = db.query(BlockedURL)
    if q:
        query = query.filter(BlockedURL.domain.ilike(f"%{q.strip().lower()}%"))
    start, end = _date_range_bounds(date_from, date_to)
    if start:
        query = query.filter(BlockedURL.created_at >= start)
    if end:
        query = query.filter(BlockedURL.created_at <= end)
    rows = query.order_by(desc(BlockedURL.created_at)).all()
    return [
        {
            "id": r.id, "url": r.url, "domain": r.domain, "reason": r.reason,
            "source": r.source, "attack_type": r.attack_type,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.post("/global-blocks", status_code=status.HTTP_201_CREATED)
def add_global_block(
    payload: dict,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    url = str(payload.get("url") or "").strip()
    domain = _hostname(url)
    if not domain or "." not in domain:
        raise HTTPException(400, "Enter a valid URL or domain, e.g. https://example.com/login")
    if db.query(BlockedURL).filter(BlockedURL.domain == domain).first():
        raise HTTPException(409, f"{domain} is already blocked for all users")

    # Blocking a well-known site would break it for every user, so the admin
    # must confirm first (the page re-sends with confirm=true).
    if not payload.get("confirm"):
        trusted = is_trusted(url)
        rep = domain_reputation(url)
        if trusted or rep["reputable"]:
            why = rep["reason"] if rep["reputable"] else f"{domain} is on the trusted allowlist"
            return {"needs_confirm": True, "domain": domain,
                    "warning": f"{why}. Blocking it will stop every user from opening it."}

    reason = str(payload.get("reason") or "").strip() or None
    attack_type = str(payload.get("attack_type") or "").strip()[:64] or None
    row = BlockedURL(url=url, domain=domain, risk_level="High", reason=reason,
                     source="Admin (Manual)", attack_type=attack_type)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "domain": row.domain, "message": f"{domain} blocked for all users"}


@router.delete("/global-blocks/{block_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_global_block(
    block_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    row = db.query(BlockedURL).filter(BlockedURL.id == block_id).first()
    if not row:
        raise HTTPException(404, "Global block not found")
    db.delete(row)
    db.commit()

# ---------------------------------------------------------------------------
# Blacklist Report Export
# ---------------------------------------------------------------------------

@router.get("/reported-urls/export")
def export_blacklist_pdf(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    query = db.query(ReportedURL)
    start, end = _date_range_bounds(date_from, date_to)
    if start:
        query = query.filter(ReportedURL.created_at >= start)
    if end:
        query = query.filter(ReportedURL.created_at <= end)
    reports = query.order_by(desc(ReportedURL.created_at)).all()

    # Built in memory: the report was previously written to a fixed file in
    # the server's working directory.
    return _pdf_table_response(
        "PhishGuard AI - Blacklist Database Report",
        ["No", "URL", "Attack Type", "Detection Reason", "Date"],
        [
            [str(index), row.url, row.attack_type or "-", row.detection_reason or "-",
             row.created_at.strftime("%Y-%m-%d")]
            for index, row in enumerate(reports, start=1)
        ],
        col_widths_mm=[10, 80, 34, 127, 22], url_cols={1},
        filename="PhishGuard_Blacklist_Report.pdf",
    )