"""
PhishGuard AI - FastAPI backend entry point.

Interfaces served (via router mounts):
    /api/auth/*      Login, Register, Logout, Current user
    /api/scan        Interface 4 (Analyse URL)
    /api/explain     SHAP + LIME + plain-text
    /api/detections* Interface 5 (User Dashboard) + Interface 6 (History)
    /api/profile*    Interface 6 (User Profile)
    /api/admin/*     Interfaces 7-10 (admin only)

Label convention across the whole app:
    0 = Legitimate
    1 = Phishing  (positive class for reported metrics)

Run from backend/ :
    uvicorn app.main:app --reload --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import init_db
from .ml_state import DT_METRICS, MODEL, MODEL_LABEL, RF_METRICS
from .routes_admin import router as admin_router
from .routes_auth import router as auth_router
from .routes_user import router as user_router

app = FastAPI(
    title="PhishGuard AI",
    description=(
        "Phishing URL detection with Decision Tree vs Random Forest "
        "comparison, SHAP + LIME explanations, and a role-based user + "
        "admin interface."
    ),
    version="2.2.0",
)

# CORS - open in development, tighten for production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Ensure SQLite tables exist on boot.
init_db()

# Routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(admin_router)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "model_loaded": MODEL is not None,
        "deployed_model": MODEL_LABEL,
        "label_convention": {"0": "Legitimate", "1": "Phishing"},
    }


@app.get("/api/metrics")
def public_metrics():
    """
    Public model-performance snapshot.

    Kept public so the landing page can show it, but the full admin
    analytics view (with global SHAP, confusion matrix, per-class
    breakdown) lives under /api/admin/analytics.
    """
    return {
        "deployed_model": MODEL_LABEL,
        "label_convention": {"0": "Legitimate", "1": "Phishing"},
        "positive_class": "Phishing",
        "decision_tree": {
            "accuracy": DT_METRICS.get("accuracy"),
            "precision": DT_METRICS.get("precision"),
            "recall": DT_METRICS.get("recall"),
            "f1_score": DT_METRICS.get("f1_score"),
        },
        "random_forest": {
            "accuracy": RF_METRICS.get("accuracy"),
            "precision": RF_METRICS.get("precision"),
            "recall": RF_METRICS.get("recall"),
            "f1_score": RF_METRICS.get("f1_score"),
        },
        "n_train": DT_METRICS.get("n_train"),
        "n_test": DT_METRICS.get("n_test"),
        "n_features": DT_METRICS.get("n_features"),
    }
