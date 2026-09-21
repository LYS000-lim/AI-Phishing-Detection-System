import os

from dotenv import load_dotenv

# Load backend/.env (SMTP credentials, secrets, etc.) before anything else
# reads os.environ. Path is relative to this file, not the process's cwd,
# since uvicorn is launched with --app-dir backend from the repo root.
# Safe to call even if the file doesn't exist.
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import init_db
from .ml_state import DT_METRICS, MODEL, MODEL_LABEL, RF_METRICS
from .routes_admin import router as admin_router
from .routes_auth import router as auth_router
from .routes_user import router as user_router
from .routes_extension import router as extension_router

app = FastAPI(
    title="PhishGuard AI",
    description=(
        "Phishing URL detection with Decision Tree vs Random Forest "
        "comparison, SHAP + LIME explanations, and a role-based user + "
        "admin interface."
    ),
    version="2.2.0",
)

# CORS - restricted to the known frontend origin(s). Override/extend via
# the PHISHGUARD_CORS_ORIGINS env var (comma-separated) when deploying.
_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
_allowed_origins = [
    o.strip()
    for o in os.environ.get("PHISHGUARD_CORS_ORIGINS", _default_origins).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure SQLite tables exist on boot.
init_db()

# Routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(admin_router)
app.include_router(extension_router)


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
