"""
Automated, rule-based quality scoring for the explanation pipeline output
(attack analysis, "Why was this detected?", Evidence cards, SHAP/LIME
presentation). This does NOT grade correctness of the phishing/legitimate
verdict itself -- that's fp_category_tests.py's job. This scores whether the
EXPLANATION TEXT around a given verdict is well-formed, non-duplicate,
non-jargon-leaking, and internally consistent, as a percentage per
dimension, per URL.

All checks are deterministic and documented inline so they can be justified
in the FYP report/defense: each score is the percentage of a fixed checklist
that passed, not a subjective judgment call. A score of None means the
dimension does not apply to that URL (e.g. Attack Analysis correctness only
applies to URLs that are truly phishing AND were predicted phishing -- for a
false positive there's no "correct" attack technique to check against).
"""
import re

from app.explanations import FEATURE_TITLES

# ---------------------------------------------------------------------------
# 1. Attack Analysis correctness
# ---------------------------------------------------------------------------
# Ground truth derived from fp_category_tests.py's own category names, which
# already encode the intended attack behaviour (e.g. "ip_phish" URLs are
# IP-hosted by construction). Only categories with an unambiguous expected
# technique are listed; categories not listed here are excluded from this
# score (returns None) rather than guessed at.
CATEGORY_EXPECTED_TECHNIQUES = {
    "ip_phish": {"IP Address Hosting"},
    "typosquat_hyphen_phish": {"Typosquatting", "Brand Impersonation"},
    "brand_in_path_phish": {"Brand Impersonation", "Credential Harvesting"},
    "obfuscated_phish": {"URL Obfuscation"},
}

JARGON_PATTERN = re.compile(r"\bSHAP\b|\bLIME\b|[+-]\d\.\d{2,}")


def score_attack_analysis(category: str, expected: int, result: dict):
    """
    % match between the technique(s) actually reported and the technique(s)
    the URL's category implies it should have. Only scored for URLs that
    are genuinely phishing (expected == 1) AND were correctly caught
    (predicted phishing) -- a missed/false-positive verdict is an accuracy
    problem, not an explanation-quality problem, so it's excluded (None)
    here rather than double-penalized.
    """
    if expected != 1 or result["label"] != 1:
        return None
    expected_set = CATEGORY_EXPECTED_TECHNIQUES.get(category)
    if not expected_set:
        return None

    attack = result["attack_analysis"]
    if not attack:
        return 0.0
    techniques = set(attack.get("techniques") or [])
    return 100.0 if techniques & expected_set else 0.0


# ---------------------------------------------------------------------------
# 2. "Why was this detected?" quality
# ---------------------------------------------------------------------------
def score_why_detected(result: dict):
    """
    Checklist (each worth an equal share of 100%):
      1. Not empty, and not too short (phishing needs >=2 bullets, since a
         single generic bullet was the exact complaint fixed in round 3).
      2. No bullet is a verbatim duplicate of an Attack Analysis indicator
         sentence (the exact repetition bug fixed in round 4).
      3. No raw ML jargon or leaked numeric contribution values (a user-
         facing section should never show "SHAP" or "+0.229...").
      4. Bullets are substantive (average >=6 words), not one-line stubs
         like "TLD contributed."
    """
    bullets = result["why_detected"]
    attack = result["attack_analysis"]
    checks = []

    min_bullets = 2 if result["prediction"] == "phishing" else 1
    checks.append(len(bullets) >= min_bullets)

    indicator_set = set(attack["indicators"]) if attack else set()
    checks.append(not any(b in indicator_set for b in bullets))

    checks.append(not any(JARGON_PATTERN.search(b) for b in bullets))

    avg_words = sum(len(b.split()) for b in bullets) / max(len(bullets), 1)
    checks.append(avg_words >= 6)

    return 100.0 * sum(checks) / len(checks)


# ---------------------------------------------------------------------------
# 3. Evidence card quality
# ---------------------------------------------------------------------------
_KNOWN_TITLES = set(FEATURE_TITLES.values()) | {
    "Suspicious URL Character Pattern", "Legitimate URL Character Pattern",
}


def score_evidence(result: dict):
    """
    Per-card checklist, averaged across all cards, then averaged across the
    URL's cards:
      1. "found" text present.
      2. "why_it_matters" text present.
      3. The two are not identical (would defeat the point of splitting
         them into separate lines).
      4. Title is a human-readable label (from FEATURE_TITLES), not a raw
         feature code like "URLLength" leaking into the headline.
      5. "why_it_matters" doesn't just restate the detected value verbatim
         (i.e. it's actually reasoning, not a repeated observation).
    """
    cards = result["evidence"]
    if not cards:
        return 0.0

    per_card_scores = []
    for item in cards:
        found = item.get("found") or ""
        why = item.get("why_it_matters") or ""
        checks = [
            bool(found),
            bool(why),
            found != why,
            item.get("title") in _KNOWN_TITLES,
        ]
        value_str = str(item.get("detected_value"))
        checks.append(len(value_str) <= 1 or value_str not in why)
        per_card_scores.append(sum(checks) / len(checks))

    return 100.0 * sum(per_card_scores) / len(per_card_scores)


# ---------------------------------------------------------------------------
# 4. SHAP/LIME presentation quality
# ---------------------------------------------------------------------------
def score_shap_lime(result: dict):
    """
    Per-card checklist, averaged:
      1. SHAP contribution present and finite.
      2. LIME contribution present and finite.
      3. SHAP sign is consistent with the predicted class (positive for
         phishing cards, negative for legitimate cards) -- this is actually
         guaranteed by build_evidence()'s own filter, so this check mainly
         guards against a future regression in that filter.
      4. Not BOTH SHAP and LIME are exactly zero for the same card (LIME can
         legitimately be 0 when its rule-text match misses -- see
         _lime_weight_for_feature() in explanations.py -- but SHAP-and-LIME
         both zero on a card that's supposedly a top contributor is a sign
         the evidence is uninformative).
    """
    cards = result["evidence"]
    if not cards:
        return 0.0

    want_positive = result["prediction"] == "phishing"
    per_card_scores = []
    for item in cards:
        shap_v = item.get("shap_contribution")
        lime_v = item.get("lime_contribution")
        checks = [
            isinstance(shap_v, (int, float)) and shap_v == shap_v,  # not NaN
            isinstance(lime_v, (int, float)) and lime_v == lime_v,
            (shap_v > 0) if want_positive else (shap_v < 0),
            not (shap_v == 0 and lime_v == 0),
        ]
        per_card_scores.append(sum(checks) / len(checks))

    return 100.0 * sum(per_card_scores) / len(per_card_scores)


def score_all(category: str, expected: int, result: dict) -> dict:
    return {
        "attack_analysis_score": score_attack_analysis(category, expected, result),
        "why_detected_score": score_why_detected(result),
        "evidence_score": score_evidence(result),
        "shap_lime_score": score_shap_lime(result),
    }
