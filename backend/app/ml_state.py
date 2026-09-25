import os
import re
from typing import Optional
from urllib.parse import urlparse

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

# Decision thresholds tuned on a validation split at training time (see the
# training notebook); 0.5/0.5 reproduces plain model.predict() behaviour.
THRESHOLDS = METRICS.get("thresholds", {})
PHISH_THRESHOLD = float(THRESHOLDS.get("phishing", 0.5))
UNCERTAIN_THRESHOLD = float(THRESHOLDS.get("uncertain", PHISH_THRESHOLD))


# URLs with a path or query must look clearly legitimate over HTTPS (not just
# below the Suspicious threshold) before the HTTP rule clears them: pages on
# hacked university subdomains and open redirects (m.vk.com/away.php?to=...)
# otherwise slipped through. Bare homepages keep the Suspicious threshold.
# 0.5 was chosen from the same simulation it is reported on (slightly
# optimistic).
#
# KNOWN LIMITATION (measured on all PhiUSIIL + 2024-25 feed phishing on
# reputable domains): 163 phishing-labelled URLs become "legitimate" under
# this rule. 162 are bare homepages of real services that PhiUSIIL labels
# phishing (ipify.org, coinbase.com, w3.org, ... - label noise). One is
# genuine: http://math.mak.ac.ug/aux, a page on a compromised university
# subdomain (HTTPS score 0.28 - no threshold separates it). URL text cannot
# show that a reputable domain has been hacked. No 2026 test phishing is
# affected.
HTTP_RULE_PATH_THRESHOLD = 0.5


def _http_rule_threshold(url):
    parsed = urlparse(url.strip())
    has_path = bool((parsed.path or "").strip("/")) or bool(parsed.query)
    return min(HTTP_RULE_PATH_THRESHOLD, UNCERTAIN_THRESHOLD) if has_path else UNCERTAIN_THRESHOLD


def classify_vec(vec, features, url=None):
    """explanations.classify with the deployed model and tuned thresholds,
    then the domain-reputation cap: a "phishing" verdict on a well-
    established domain (reputation.py) becomes "uncertain" (shown as
    Suspicious) with uncertain_reason "reputable_domain".

    HTTP rule: PhiUSIIL's legitimate class is 100% https://, so the model
    warns on almost every plain-http:// page. A "Suspicious" http:// URL
    becomes "legitimate" (legit_reason "http_reputable") only when BOTH the
    same URL served over HTTPS would score below the Suspicious threshold
    (below HTTP_RULE_PATH_THRESHOLD if it has a path/query) - missing HTTPS
    is the only warning signal - AND the domain is reputable
    (reputation.py: Tranco top HTTP_RULE_MAX_RANK, not a hosting /
    dynamic-DNS / shortener platform). Phishing verdicts and https:// URLs
    are never changed."""
    from .explanations import classify, is_https_only_verdict
    from .reputation import HTTP_RULE_MAX_RANK, domain_reputation
    result = classify(vec, features, MODEL, PHISH_THRESHOLD, UNCERTAIN_THRESHOLD)
    result["reputation"] = None
    result["legit_reason"] = None
    if url:
        rep = domain_reputation(url)
        result["reputation"] = rep
        if result["prediction"] == "phishing" and rep["reputable"]:
            result.update(prediction="uncertain", risk="Medium", uncertain_reason="reputable_domain")
        if (result["prediction"] == "uncertain" and rep["reputable"]
                and rep["rank"] <= HTTP_RULE_MAX_RANK
                and url.strip().lower().startswith("http://")
                and features.get("IsHTTPS") == 0
                and is_https_only_verdict(vec, MODEL, _http_rule_threshold(url))):
            result.update(prediction="legitimate", risk="Low", uncertain_reason=None,
                          legit_reason="http_reputable")
    return result


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
_global_lime_cache: Optional[np.ndarray] = None


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


def global_lime_importance(sample_size: int = 40) -> np.ndarray:
    """
    Mean-|LIME weight| per feature, approximated by averaging local LIME
    explanations over a random background sample. Unlike SHAP (one fast
    batched call), LIME retrains a local surrogate per instance, so the
    sample stays small to keep the admin analytics page responsive.
    Cached after the first computation.
    """
    global _global_lime_cache
    if _global_lime_cache is not None:
        return _global_lime_cache

    rng = np.random.default_rng(42)
    idx = rng.choice(
        len(LIME_BG), size=min(sample_size, len(LIME_BG)), replace=False,
    )

    exp = get_lime_explainer()
    totals = np.zeros(len(FEATURE_ORDER))
    counts = np.zeros(len(FEATURE_ORDER))
    name_pattern = [re.compile(rf"\b{re.escape(name)}\b") for name in FEATURE_ORDER]

    for i in idx:
        explanation = exp.explain_instance(
            LIME_BG[i], MODEL.predict_proba,
            num_features=len(FEATURE_ORDER), labels=[1],
        )
        for rule, weight in explanation.as_list(label=1):
            for feat_idx, pattern in enumerate(name_pattern):
                if pattern.search(rule):
                    totals[feat_idx] += abs(weight)
                    counts[feat_idx] += 1
                    break

    _global_lime_cache = np.divide(
        totals, counts, out=np.zeros_like(totals), where=counts > 0,
    )
    return _global_lime_cache
