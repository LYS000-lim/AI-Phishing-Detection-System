import os
import re
import warnings
from functools import lru_cache
from typing import Optional
from urllib.parse import unquote_plus, urlparse

import joblib
import numpy as np

from .features import FEATURE_ORDER, feature_vector

# The model was fitted on a DataFrame but is always called with plain arrays
# in FEATURE_ORDER; scikit-learn printed this warning on every prediction,
# flooding the server log (thousands of lines per explanation).
warnings.filterwarnings("ignore", message="X does not have valid feature names")

_HERE = os.path.dirname(os.path.abspath(__file__))
_OUTPUTS = os.path.join(_HERE, "..", "..", "outputs")


def _load(name):
    path = os.path.join(_OUTPUTS, name)
    return joblib.load(path) if os.path.exists(path) else None


MODEL = _load("deployment_model.joblib")
# The forest was trained with n_jobs=-1, so every single-URL prediction
# started a pool of threads: about 30 ms per call instead of about 10 ms,
# and one scan with its explanation makes many calls. The predictions are
# identical either way.
if MODEL is not None and hasattr(MODEL, "n_jobs"):
    MODEL.n_jobs = 1
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


# ---------------------------------------------------------------------------
# Reputable-site rule
# ---------------------------------------------------------------------------
# PhiUSIIL's legitimate URLs are bare homepages: after canonicalisation 15%
# of them have more than two host labels (mostly country endings such as
# .com.my) against 58% of its phishing, and none has a path. The model
# therefore reads a real subdomain (login., docs., journals.) and a long,
# site-generated path (document IDs, encoded folder names) as phishing
# evidence: onlinelibrary.wiley.com alone scores 0.95 and a SharePoint folder
# link 0.996. On a well-established domain those parts are chosen by the
# site itself, so on their own they are not evidence of phishing.
#
# An https:// URL that would otherwise be Suspicious becomes Legitimate
# (legit_reason "reputable_site") when ALL of these hold:
#   - the domain is in the Tranco top HTTP_RULE_MAX_RANK (the HTTP rule's
#     stricter cut-off) and is not one of reputation.ABUSED_PLATFORMS, whose
#     subdomains belong to other people (a DOCUMENT_SERVICES host such as
#     SharePoint or Google Docs is allowed, with a "check who shared it"
#     note);
#   - the model would not warn about the site's own homepage (score below
#     the Suspicious threshold; google.com.my scores 0.52 only because
#     .com.my adds a label);
#   - the address carries no lure (lure_signals): login or payment wording,
#     another company's brand name, a link to another website, a user@
#     prefix or a page in the website software's folders (wp-admin ...) -
#     what a phishing page on a shared or hacked site needs to deceive.
# Like the HTTP rule, it cannot recognise a hacked reputable site whose
# address contains none of these, nor phishing in a shared document.
REPUTABLE_SITE_MAX_SCORE = UNCERTAIN_THRESHOLD
_EMBEDDED_HOST = re.compile(r"(?:https?:/+|www\.)([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", re.I)
# Folders of the website software that visitors never open as pages: a page
# there is how phishing hides on a hacked WordPress or shared-hosting site.
_SOFTWARE_FOLDER = re.compile(
    r"/(?:wp-includes|wp-admin|wp-content/(?:plugins|themes)|\.well-known|cgi-bin)/", re.I)


@lru_cache(maxsize=4096)
def homepage_score(domain: str) -> float:
    """Model score of the domain's own homepage, https://<domain>."""
    return float(MODEL.predict_proba(feature_vector("https://" + domain))[0][1])


def lure_signals(url: str, domain: str) -> list:
    """Signs of a phishing lure in the parts of an address that a site or
    its users choose (subdomain, path, query and fragment), as short
    phrases. An empty list means none was found."""
    from .brands import (FEED_BRANDS, MODEL_BRANDS, MY_BRANDS, impersonated_brand,
                         lookalike_brand, malaysian_brand)
    from .features import _tokens, suspicious_word_count
    from .reputation import _extract_icann
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    sub = host[: -len(domain)].rstrip(".") if domain and host.endswith(domain) else host
    rest = " ".join(unquote_plus(part) for part in (parsed.path, parsed.query, parsed.fragment) if part)
    text = f"{sub} {rest}".lower()
    found = []
    if suspicious_word_count("x://" + text):
        found.append("login or payment wording")
    tokens = set(_tokens(text))
    names = set(FEED_BRANDS) | set(MY_BRANDS) | {a for m in MODEL_BRANDS.values() for a in m["aliases"]}
    own = domain.split(".")[0]
    if (any(len(n) >= 4 and n in tokens and n not in own for n in names)
            or impersonated_brand(url) or malaysian_brand(url) or lookalike_brand(url)):
        found.append("another company's brand name")
    for match in _EMBEDDED_HOST.finditer(rest):
        other = _extract_icann(match.group(1).lower()).top_domain_under_public_suffix
        if other and other != domain:
            found.append(f"a link to another website ({other})")
            break
    if parsed.username is not None:
        found.append("a user@ prefix that hides the real host")
    if _SOFTWARE_FOLDER.search(parsed.path or ""):
        found.append("a page hidden in the website software's folders")
    return found


def _apply_stage2(result: dict, rep: dict, url: str) -> None:
    """Stage 2 (stage2.py): the URL score combined with the domain's age
    decides the verdict level when the age is known (in place)."""
    from . import stage2
    from .reputation import is_user_content_host
    if rep.get("shortener") or is_user_content_host(url):
        return
    s2 = stage2.score(result["p_phish"], rep.get("domain", ""))
    if s2 is None:
        return
    result["stage2"] = s2
    before, after = result["prediction"], s2["level"]
    if after == "legitimate" and before != "legitimate":
        # A hacked old website keeps its age, so a strong lure in the
        # address (another company's brand, a link to another website, a
        # user@ prefix, a page in the site software's folders) keeps the
        # result at Suspicious. Login wording alone does not: genuine login
        # pages use it too.
        lures = lure_signals(url, rep.get("domain", ""))
        if any(not lure.startswith("login or payment") for lure in lures):
            result["lures"] = lures
            after = "uncertain"
    if before == after:
        return
    order = {"legitimate": 0, "uncertain": 1, "phishing": 2}
    raised = order[after] > order[before]
    s2["changed"] = "raised" if raised else "lowered"
    result.update(prediction=after, legit_reason=None, escalated_by=None,
                  risk={"phishing": "High", "uncertain": "Medium", "legitimate": "Low"}[after],
                  uncertain_reason=("new_domain" if raised else "established_domain") if after == "uncertain" else None)
    if after == "phishing":
        result["escalated_by"] = "new_domain"
    elif after == "legitimate":
        result["legit_reason"] = "established_domain"


def classify_vec(vec, features, url=None):
    """explanations.classify with the deployed model and tuned thresholds,
    then stage 2 (stage2.py: the URL score combined with the domain's age,
    when the age is known - uncertain_reason / escalated_by "new_domain",
    uncertain_reason / legit_reason "established_domain" when it changes
    the verdict level), then the domain-reputation cap: a "phishing" verdict on a well-
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
    are never changed.

    Reputable-site rule (see above): a Suspicious https:// URL on a
    well-established domain becomes "legitimate" (legit_reason
    "reputable_site") when the site's own homepage scores as legitimate and
    the address carries no lure.

    Short-link rule: a link on a URL shortener (reputation.SHORTENERS) hides
    its destination, so it is "uncertain" (uncertain_reason "short_link")
    whatever the model scored.

    Brand rule (brands.py): a known phishing-target brand (FEED_BRANDS or
    MY_BRANDS) in the hostname of a domain that is not well established
    raises the verdict one step - legitimate -> uncertain (uncertain_reason
    "brand_impersonation"), uncertain -> phishing (escalated_by
    "brand_impersonation"). A look-alike spelling of a brand counts the
    same way ("lookalike" holds the imitating text): a one-letter
    misspelling raises the verdict one step, while look-alike characters
    (g00gle, paypa1, punycode homographs) make it phishing."""
    from .explanations import classify, is_https_only_verdict
    from .brands import brand_display, impersonated_brand, lookalike_brand, malaysian_brand
    from .reputation import HTTP_RULE_MAX_RANK, domain_reputation
    result = classify(vec, features, MODEL, PHISH_THRESHOLD, UNCERTAIN_THRESHOLD)
    result["reputation"] = None
    result["legit_reason"] = None
    result["escalated_by"] = None
    result["brand"] = None
    result["lookalike"] = None
    result["lures"] = []
    result["stage2"] = None
    if url:
        rep = domain_reputation(url)
        result["reputation"] = rep
        _apply_stage2(result, rep, url)
        if result["prediction"] == "phishing" and rep["reputable"]:
            result.update(prediction="uncertain", risk="Medium", uncertain_reason="reputable_domain",
                          escalated_by=None)
        if (result["prediction"] == "uncertain" and rep["reputable"]
                and rep["rank"] <= HTTP_RULE_MAX_RANK
                and url.strip().lower().startswith("http://")
                and features.get("IsHTTPS") == 0
                and is_https_only_verdict(vec, MODEL, _http_rule_threshold(url))):
            result.update(prediction="legitimate", risk="Low", uncertain_reason=None,
                          legit_reason="http_reputable")
        if (result["prediction"] == "uncertain" and rep["reputable"]
                and rep["rank"] <= HTTP_RULE_MAX_RANK
                and (rep["shared"] or not rep["abused"])
                and result["uncertain_reason"] in ("reputable_domain", "borderline", "established_domain")
                and url.strip().lower().startswith("https://")
                and homepage_score(rep["domain"]) < REPUTABLE_SITE_MAX_SCORE):
            # "lures" lets the explanation name what kept the warning.
            result["lures"] = lure_signals(url, rep["domain"])
            if not result["lures"]:
                result.update(prediction="legitimate", risk="Low", uncertain_reason=None,
                              legit_reason="reputable_site")
        parsed = urlparse(url.strip())
        if rep.get("shortener") and ((parsed.path or "").strip("/") or parsed.query):
            result.update(prediction="uncertain", risk="Medium", uncertain_reason="short_link",
                          legit_reason=None)
            return result
        brand = impersonated_brand(url) or malaysian_brand(url)
        lookalike = None if brand else lookalike_brand(url)
        if (brand or lookalike) and not rep["reputable"] and result["prediction"] != "phishing":
            result["brand"] = brand_display(brand or lookalike[0])
            if lookalike:
                result["lookalike"] = lookalike[1]
            if result["prediction"] == "legitimate" and not (lookalike and lookalike[2] == "characters"):
                result.update(prediction="uncertain", risk="Medium",
                              uncertain_reason="brand_impersonation", legit_reason=None)
            else:
                result.update(prediction="phishing", risk="High", uncertain_reason=None,
                              legit_reason=None, escalated_by="brand_impersonation")
    return result


def model_info() -> dict:
    """Descriptor the frontend puts on the result card."""
    return {
        "name": MODEL_LABEL,
        "class": type(MODEL).__name__ if MODEL else None,
        "n_features": len(FEATURE_ORDER),
    }


# ---------------------------------------------------------------------------
# What-if: "what would change this result?"
# ---------------------------------------------------------------------------
_TYPICAL = None
_BINARY = {"IsDomainIP", "HasObfuscation", "IsHTTPS", "HasBrandOutsideDomain"}


def _typical_values():
    """10th/50th/90th percentile of each feature per class, built by
    backend/tests/build_typical_values.py. Empty if the file is missing."""
    global _TYPICAL
    if _TYPICAL is None:
        import json
        path = os.path.join(_OUTPUTS, "feature_typical_values.json")
        _TYPICAL = json.load(open(path)) if os.path.exists(path) else {}
    return _TYPICAL


def what_if_changes(vec, contrib, prediction, limit=3):
    """For the `limit` features whose SHAP value supports the verdict, set
    each one (alone) to a value typical of the opposite class and re-score.
    Phishing/uncertain verdicts try legitimate values and keep the one that
    lowers the score most; legitimate verdicts try phishing values and keep
    the one that raises it most. Features already at a typical value are
    skipped."""
    typical = _typical_values()
    if MODEL is None or not typical:
        return []
    towards_legit = prediction != "legitimate"
    ref = typical["legitimate" if towards_legit else "phishing"]
    order = np.argsort(-contrib if towards_legit else contrib)
    base = float(MODEL.predict_proba(vec)[0][1])
    out = []
    for i in order:
        if len(out) >= limit or (contrib[i] <= 0 if towards_legit else contrib[i] >= 0):
            break
        name = FEATURE_ORDER[i]
        current = float(vec[0, i])
        candidates = {0.0, 1.0} if name in _BINARY else set(ref.get(name, []))
        candidates.discard(current)
        best = None
        for value in candidates:
            changed = vec.copy()
            changed[0, i] = value
            score = float(MODEL.predict_proba(changed)[0][1])
            if best is None or (score < best[1] if towards_legit else score > best[1]):
                best = (value, score)
        if best and (best[1] <= base - 0.005 if towards_legit else best[1] >= base + 0.005):
            out.append({
                "feature": name,
                "current": round(current, 4),
                "changed": round(best[0], 4),
                "score_now": round(base, 4),
                "score_changed": round(best[1], 4),
                "model_result": ("phishing" if best[1] >= PHISH_THRESHOLD
                                 else "suspicious" if best[1] >= UNCERTAIN_THRESHOLD
                                 else "legitimate"),
            })
    return out


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
