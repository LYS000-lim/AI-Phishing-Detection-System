"""
Explanation-quality evaluation: reuses the same categorized URL set as
fp_category_tests.py (not a separate file -- imported directly so the two
suites never drift apart) but, instead of just checking predicted vs
expected, runs the full /api/explain pipeline (SHAP, LIME, attack analysis,
Why-detected, Evidence cards, confidence category) per URL so a human can
read and judge the explanation text quality, not just accuracy.

Also scores explanation QUALITY (not just accuracy) on four dimensions --
Attack Analysis correctness, Why-detected quality, Evidence card quality,
SHAP/LIME presentation quality -- as a 0-100% per URL. See
explanation_scoring.py for the exact, documented checklist behind each
score; this file only wires those scores into the report/CSV.

Run: python backend/tests/explanation_eval.py
Saves:
  outputs/explanation_eval_report.md   (human-readable, one block per URL --
                                         read this to judge explanation quality)
  outputs/explanation_eval_summary.csv (accuracy + all 4 quality scores per
                                         URL, plus category/overall averages
                                         printed to the console)
Label convention: 0 = legitimate, 1 = phishing (matches app/features.py).
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import pandas as pd

from app.explanations import build_evidence, build_reason_bullets, risk_level
from app.features import FEATURE_ORDER, extract_features, feature_vector
from app.ml_state import MODEL, get_lime_explainer, get_shap_explainer, model_info
from app.phishing_type import detect_phishing_type
from explanation_scoring import score_all
from fp_category_tests import TEST_CASES


def confidence_label(value: float) -> str:
    """Mirrors frontend/src/components/user/Scanner.jsx's confidenceInfo()."""
    pct = value * 100
    if pct >= 80:
        return "High"
    if pct >= 60:
        return "Medium"
    return "Low"


def explain_url(url: str) -> dict:
    vec = feature_vector(url)
    features = extract_features(url)

    label = int(MODEL.predict(vec)[0])
    proba = MODEL.predict_proba(vec)[0]
    p_phish = float(proba[1])
    prediction = "phishing" if label == 1 else "legitimate"
    risk = risk_level(p_phish)
    confidence = float(max(proba))

    shap_exp = get_shap_explainer()
    shap_vals = shap_exp.shap_values(vec)
    arr = np.asarray(shap_vals)
    if arr.ndim == 3:
        contrib = arr[0, :, 1]
    elif isinstance(shap_vals, list):
        contrib = np.asarray(shap_vals[1])[0]
    else:
        contrib = arr[0]

    shap_out = sorted(
        (
            {"feature": f, "shap_value": round(float(v), 5)}
            for f, v in zip(FEATURE_ORDER, contrib)
        ),
        key=lambda d: abs(d["shap_value"]),
        reverse=True,
    )[:10]

    lime_exp = get_lime_explainer()
    explanation = lime_exp.explain_instance(
        vec[0], MODEL.predict_proba, num_features=10, labels=[1],
    )
    lime_out = [
        {"rule": rule, "weight": round(float(w), 5)}
        for rule, w in explanation.as_list(label=1)
    ]

    attack_analysis = (
        detect_phishing_type(url, features) if prediction == "phishing" else None
    )
    why_detected = build_reason_bullets(
        prediction, features, shap_out, attack_analysis=attack_analysis, limit=4,
    )
    evidence = build_evidence(prediction, features, shap_out, lime_out, limit=3)

    return {
        "prediction": prediction,
        "label": label,
        "p_phish": p_phish,
        "risk": risk,
        "confidence": confidence,
        "confidence_label": confidence_label(confidence),
        "attack_analysis": attack_analysis,
        "why_detected": why_detected,
        "evidence": evidence,
    }


def _fmt_score(value) -> str:
    return "N/A" if value is None else f"{value:.0f}%"


def render_markdown_block(category, url, expected, result, scores) -> str:
    correct = result["label"] == expected
    lines = [
        f"## [{category}] {url}",
        "",
        f"- Expected: {'Phishing' if expected == 1 else 'Legitimate'} | "
        f"Predicted: {'Phishing' if result['label'] == 1 else 'Legitimate'} | "
        f"{'CORRECT' if correct else '*** WRONG ***'}",
        f"- p_phish: {result['p_phish']:.3f} | Risk: {result['risk']} | "
        f"Confidence: {result['confidence_label']} ({result['confidence']*100:.1f}%)",
        f"- **Quality scores** -- Attack Analysis: {_fmt_score(scores['attack_analysis_score'])} | "
        f"Why-detected: {_fmt_score(scores['why_detected_score'])} | "
        f"Evidence: {_fmt_score(scores['evidence_score'])} | "
        f"SHAP/LIME: {_fmt_score(scores['shap_lime_score'])}",
        "",
    ]

    attack = result["attack_analysis"]
    if attack:
        lines.append(f"**Attack Category:** {attack['category']}")
        lines.append(f"**Attack Technique:** {attack['technique']}")
        for ind in attack["indicators"]:
            lines.append(f"- {ind}")
        lines.append("")

    lines.append("**Why was this detected?**")
    for bullet in result["why_detected"]:
        lines.append(f"- {bullet}")
    lines.append("")

    lines.append("**AI Explanation Evidence:**")
    for item in result["evidence"]:
        value = item["detected_value"]
        shown_value = round(value, 5) if isinstance(value, float) else value
        lines.append(f"- *{item['title']}* (`{item['feature']}` = {shown_value})")
        lines.append(f"  - What the AI found: {item['found']}")
        lines.append(f"  - Why this matters: {item['why_it_matters']}")
        lines.append(
            f"  - SHAP: {item['shap_contribution']:+.5f} | "
            f"LIME: {item['lime_contribution']:+.5f} | {item['support']}"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def main():
    outputs_dir = os.path.join(ROOT, "outputs")
    print(f"Model: {model_info()}")

    md_parts = [
        "# Explanation-quality evaluation report",
        "",
        f"Reuses the {sum(len(v) for v in TEST_CASES.values())} categorized URLs "
        "from `backend/tests/fp_category_tests.py`. Read each block below to judge "
        "whether the Attack Analysis / Why-detected / Evidence text reads well and "
        "matches the URL's actual behaviour -- this script does not change or "
        "re-check the model itself (see fp_category_tests.py for that).",
        "",
    ]
    summary_rows = []

    for category, cases in TEST_CASES.items():
        for url, expected in cases:
            result = explain_url(url)
            scores = score_all(category, expected, result)
            md_parts.append(render_markdown_block(category, url, expected, result, scores))
            summary_rows.append({
                "category": category,
                "url": url,
                "expected": expected,
                "predicted": result["label"],
                "correct": result["label"] == expected,
                "risk": result["risk"],
                "confidence_label": result["confidence_label"],
                "attack_analysis_score": scores["attack_analysis_score"],
                "why_detected_score": scores["why_detected_score"],
                "evidence_score": scores["evidence_score"],
                "shap_lime_score": scores["shap_lime_score"],
            })

    md_path = os.path.join(outputs_dir, "explanation_eval_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_parts))

    summary_df = pd.DataFrame(summary_rows)
    csv_path = os.path.join(outputs_dir, "explanation_eval_summary.csv")
    summary_df.to_csv(csv_path, index=False)

    cat_summary = summary_df.groupby("category").agg(
        n=("correct", "size"), accuracy=("correct", "mean")
    ).round(3)
    print(cat_summary)
    print(f"\nOverall: {len(summary_df)} URLs, accuracy={summary_df['correct'].mean():.3f}")

    score_cols = [
        "attack_analysis_score", "why_detected_score",
        "evidence_score", "shap_lime_score",
    ]
    print("\nExplanation quality scores (mean %, N/A rows excluded per dimension):")
    quality_summary = summary_df[score_cols].mean(skipna=True).round(1)
    print(quality_summary.to_string())
    n_attack_scored = summary_df["attack_analysis_score"].notna().sum()
    print(f"(attack_analysis_score computed on {n_attack_scored} correctly-caught, "
          "ground-truth-mapped phishing URLs; N/A elsewhere by design)")

    print(f"\nSaved report: {md_path}")
    print(f"Saved summary: {csv_path}")


if __name__ == "__main__":
    main()
