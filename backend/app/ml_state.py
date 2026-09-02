"""
Central place where the trained models and explainers live.

Loaded once at startup by main.py. Importing this module for the first
time also loads the deployment model into memory.
"""

import os
from typing import Optional

import joblib
import numpy as np

from .features import FEATURE_ORDER

_HERE = os.path.dirname(os.path.abspath(__file__))
_OUTPUTS = os.path.join(_HERE, "..", "..", "outputs")


def _load(name):
    path = os.path.join(_OUTPUTS, name)
    return joblib.load(path) if os.path.exists(path) else None


MODEL = _load("deployment_model.joblib")
METRICS = _load("deployment_metrics.joblib") or {}
LIME_BG = np.load(os.path.join(_OUTPUTS, "lime_background.npy"))

DT_METRICS = METRICS.get("decision_tree", {})
RF_METRICS = METRICS.get("random_forest", {})
MODEL_LABEL = METRICS.get("winner", type(MODEL).__name__ if MODEL else "unknown")


def model_info() -> dict:
    """Descriptor the frontend puts on the result card."""
    return {
        "name": MODEL_LABEL,
        "class": type(MODEL).__name__ if MODEL else None,
        "n_features": len(FEATURE_ORDER),
    }


# ---------------------------------------------------------------------------
# Explainers - lazily built the first time they're needed
# ---------------------------------------------------------------------------
_shap_explainer = None
_lime_explainer = None
_global_shap_cache: Optional[np.ndarray] = None


def get_shap_explainer():
    global _shap_explainer
    if _shap_explainer is None:
        import shap
        _shap_explainer = shap.TreeExplainer(MODEL)
    return _shap_explainer


def get_lime_explainer():
    global _lime_explainer
    if _lime_explainer is None:
        from lime.lime_tabular import LimeTabularExplainer
        _lime_explainer = LimeTabularExplainer(
            LIME_BG,
            feature_names=FEATURE_ORDER,
            class_names=["Legitimate", "Phishing"],
            mode="classification",
            random_state=42,
        )
    return _lime_explainer


def global_shap_importance(sample_size: int = 500) -> np.ndarray:
    """
    Mean-|SHAP| per feature, computed once and cached.
    Uses a random subsample of the LIME background matrix to stay fast.
    """
    global _global_shap_cache
    if _global_shap_cache is not None:
        return _global_shap_cache

    rng = np.random.default_rng(42)
    idx = rng.choice(
        len(LIME_BG), size=min(sample_size, len(LIME_BG)), replace=False,
    )
    sample = LIME_BG[idx]

    exp = get_shap_explainer()
    values = exp.shap_values(sample)
    arr = np.asarray(values)
    if arr.ndim == 3:                       # (samples, features, classes)
        contrib = arr[..., 1]
    elif isinstance(values, list):          # [class0, class1]
        contrib = np.asarray(values[1])
    else:
        contrib = arr

    _global_shap_cache = np.mean(np.abs(contrib), axis=0)
    return _global_shap_cache
