"""
The score the result pages show, on one scale for every verdict path.

The URL model and the domain-age model (stage2.py) each have their own
warning thresholds (URL model: Suspicious from 73%, Phishing from 89%;
domain-age model: 40% / 66%), so their raw outputs cannot be compared on
one page: a raw 70% URL score is Legitimate while a raw 46% domain-age
score is Suspicious. Each raw output is therefore mapped, piecewise
linearly, onto a common Risk Score whose warning levels are the same for
both models:

    below the model's Suspicious threshold   -> 0% - 50%   (Legitimate)
    Suspicious threshold to Phishing one      -> 50% - 80%  (Suspicious)
    Phishing threshold and above              -> 80% - 100% (Phishing)

The mapping keeps the order of scores, so every verdict stays exactly the
same; only the number shown changes. It is a display scale aligned to the
system's warning levels, not a re-estimated probability. Stored values
(Detection.phishing_probability) remain the URL model's raw output.

When a rule after the models decided the verdict (a brand look-alike, the
live page check, domain reputation, ...), no model score lies in the
verdict's band, so the score shown is the URL model's score placed inside
that band (band floor + model score x band width): it always agrees with
the verdict, and within the band a riskier address still scores higher.
A rule-decided Legitimate result uses the lower half of its band (0% -
25%): the rule cleared the address, so it should not look borderline.
"""

SUSPICIOUS_AT = 0.5
PHISHING_AT = 0.8
_BANDS = {"legitimate": (0.0, SUSPICIOUS_AT), "uncertain": (SUSPICIOUS_AT, PHISHING_AT),
          "phishing": (PHISHING_AT, 1.0)}
# Where a rule-decided verdict's score is placed (see above).
_RULE_BANDS = {**_BANDS, "legitimate": (0.0, SUSPICIOUS_AT / 2)}

# Reasons whose verdict is the domain-age model's own level.
_AGE_REASONS = {"new_domain", "established_domain"}


def rescale(p: float, uncertain_thr: float, phish_thr: float) -> float:
    """Raw model output -> Risk Score on the common scale (see above)."""
    p = min(max(float(p), 0.0), 1.0)
    if p < uncertain_thr:
        return SUSPICIOUS_AT * p / uncertain_thr
    if p < phish_thr:
        return SUSPICIOUS_AT + (PHISHING_AT - SUSPICIOUS_AT) * (p - uncertain_thr) / (phish_thr - uncertain_thr)
    return PHISHING_AT + (1 - PHISHING_AT) * (p - phish_thr) / (1 - phish_thr)


def level(score: float) -> str:
    """The verdict level a Risk Score falls in."""
    return "phishing" if score >= PHISHING_AT else "uncertain" if score >= SUSPICIOUS_AT else "legitimate"


def in_band(score: float, prediction: str) -> float:
    """A score in [0, 1] placed inside the verdict's band (for a rule)."""
    low, high = _RULE_BANDS[prediction]
    # Kept just below the band's top, which is the next band's floor.
    return low + min(max(score, 0.0), 0.998) * (high - low)


def decided_by(verdict: dict) -> str:
    """Short name of the rule that set the verdict level."""
    ur, lr, eb = verdict.get("uncertain_reason"), verdict.get("legit_reason"), verdict.get("escalated_by")
    if "brand_impersonation" in (ur, eb):
        return "Brand look-alike rule" if verdict.get("lookalike") else "Brand name rule"
    if "page_check" in (lr, eb):
        return "Live page check"
    if lr == "reputable_site":
        return "Domain reputation rule"
    if ur == "reputable_domain":
        return "Domain reputation cap"
    if lr == "http_reputable":
        return "HTTP and domain reputation rule"
    if ur == "https_only":
        return "Missing-HTTPS rule"
    if ur == "short_link":
        return "Short-link rule"
    if "new_domain" in (ur, eb):
        return "Domain-age check, capped at Suspicious"
    if "established_domain" in (ur, lr):
        return "Domain-age check, kept at Suspicious by a lure in the address"
    return "Post-model rule"


def score_view(verdict: dict, uncertain_thr: float, phish_thr: float) -> dict:
    """
    {"source": "url_model" | "domain_age" | "rule",
     "risk_score": the score shown, always in the verdict's band (for a
                   rule, the URL model's score placed in that band),
     "confidence": share of the score on the verdict's side (None for a
                   Suspicious result or a rule, whose page text names the
                   rule's own confidence level),
     "url_score": the URL model on the common scale,
     "age_score": the domain-age model on the common scale, or None,
     "decided_by": rule name when source is "rule", else None,
     "levels": {"suspicious": 0.5, "phishing": 0.8}}
    """
    prediction = verdict["prediction"]
    url_score = rescale(verdict["p_phish"], uncertain_thr, phish_thr)
    s2 = verdict.get("stage2")
    age_score = rescale(s2["p"], s2["thresholds"]["uncertain"], s2["thresholds"]["phishing"]) if s2 else None
    reasons = {verdict.get("uncertain_reason"), verdict.get("legit_reason"), verdict.get("escalated_by")} - {None}

    source, score = "rule", None
    if not reasons - {"borderline"} - _AGE_REASONS:
        # No rule outside the two models: the verdict is the domain-age
        # model's level when the age is known, else the URL model's.
        candidate, name = (age_score, "domain_age") if age_score is not None else (url_score, "url_model")
        if level(candidate) == prediction:
            source, score = name, candidate
    if score is None:
        score = in_band(url_score, prediction)

    confidence = None
    if source != "rule" and prediction != "uncertain":
        confidence = score if prediction == "phishing" else 1 - score
    return {
        "source": source,
        "risk_score": None if score is None else round(score, 4),
        "confidence": None if confidence is None else round(confidence, 4),
        "url_score": round(url_score, 4),
        "age_score": None if age_score is None else round(age_score, 4),
        "decided_by": decided_by(verdict) if source == "rule" else None,
        "levels": {"suspicious": SUSPICIOUS_AT, "phishing": PHISHING_AT},
    }


def stored_score(prediction: str, p_phish: float):
    """(score, confidence) for a saved record without a stored score: the
    URL model's score on the common scale, placed in the verdict's band
    when a rule decided (which the record no longer says)."""
    from .ml_state import PHISH_THRESHOLD, UNCERTAIN_THRESHOLD
    if prediction not in _BANDS:
        return None, None
    score = rescale(p_phish, UNCERTAIN_THRESHOLD, PHISH_THRESHOLD)
    if level(score) != prediction:
        return round(in_band(score, prediction), 4), None
    confidence = None if prediction == "uncertain" else score if prediction == "phishing" else 1 - score
    return round(score, 4), None if confidence is None else round(confidence, 4)


# A trusted-allowlist result: no model runs, shown as 0% / 100% confident.
TRUSTED_SCORE = {"source": "trusted", "risk_score": 0.0, "confidence": 1.0, "url_score": None,
                 "age_score": None, "decided_by": None,
                 "levels": {"suspicious": SUSPICIOUS_AT, "phishing": PHISHING_AT}}


# Dashboard and log counts use the verdict users were shown.
VERDICT_KEY = {"phishing": "phishing", "uncertain": "suspicious", "legitimate": "legitimate"}


def verdict_counts(predictions) -> dict:
    """{"phishing", "suspicious", "legitimate"} counts of shown verdicts."""
    counts = {"phishing": 0, "suspicious": 0, "legitimate": 0}
    for prediction in predictions:
        counts[VERDICT_KEY.get(prediction, "legitimate")] += 1
    return counts


def shown_score(detection) -> tuple:
    """(score, confidence) a saved Detection's page showed."""
    if detection.risk_score is not None:
        return detection.risk_score, detection.score_confidence
    return stored_score(detection.prediction, detection.phishing_probability)
