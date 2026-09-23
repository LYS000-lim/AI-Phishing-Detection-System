"""
Large-scale false-positive rate check on real, held-out legitimate URLs
(not used in training). Complements fp_category_tests.py's small curated
set with a statistically meaningful sample size.

Sources:
- tranco_legitimate.csv : 50,000 real legitimate URLs (Tranco top list)
- top-1m.csv            : top 5,000 domains by popularity rank
- additional_legitimate_urls.csv + additional_opensource_urls.csv :
                          ~760 real legitimate DEEP LINKS (docs, repos,
                          versioned paths) - never used in training

Reports the raw 0.5 false-positive rate, plus what the live app shows
with the tuned thresholds: hard "phishing" verdicts vs. "uncertain".

Run: python backend/tests/batch_eval.py
Saves: outputs/batch_eval_results.csv (per-URL) + prints a summary.
Label convention: 0 = legitimate, 1 = phishing.
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))

import joblib
import numpy as np
import pandas as pd

from app.features import URL_ONLY_FEATURES, compute_features

TOP_N_DOMAINS = 5000
pd.set_option("display.width", 200)
pd.set_option("display.max_columns", None)


def _predict(urls, model, tld_lookup, char_lookup):
    feats = [compute_features(u, tld_lookup, char_lookup) for u in urls]
    X = pd.DataFrame(feats)[URL_ONLY_FEATURES].astype(float)
    proba = model.predict_proba(X.values)[:, 1]
    pred = (proba >= 0.5).astype(int)
    return pred, proba


def main():
    outputs_dir = os.path.join(ROOT, "outputs")
    tld_lookup = joblib.load(os.path.join(outputs_dir, "tld_probability_lookup.joblib"))
    char_lookup = joblib.load(os.path.join(outputs_dir, "char_probability_lookup.joblib"))
    model = joblib.load(os.path.join(outputs_dir, "deployment_model.joblib"))
    thresholds = joblib.load(os.path.join(outputs_dir, "deployment_metrics.joblib")).get("thresholds", {})
    t_phish = float(thresholds.get("phishing", 0.5))
    t_unc = float(thresholds.get("uncertain", t_phish))

    rows = []

    tranco = pd.read_csv(os.path.join(ROOT, "tranco_legitimate.csv"))
    urls = tranco["url"].astype(str).tolist()
    pred, proba = _predict(urls, model, tld_lookup, char_lookup)
    for u, p, pr in zip(urls, pred, proba):
        rows.append({"source": "tranco_legitimate", "url": u, "expected": 0,
                     "predicted": int(p), "p_phish": round(float(pr), 3)})

    top = pd.read_csv(os.path.join(ROOT, "top-1m.csv"), header=None,
                       names=["rank", "domain"], nrows=TOP_N_DOMAINS)
    top_urls = ["https://" + d for d in top["domain"].astype(str)]
    pred2, proba2 = _predict(top_urls, model, tld_lookup, char_lookup)
    for u, p, pr in zip(top_urls, pred2, proba2):
        rows.append({"source": "top_1m_domains", "url": u, "expected": 0,
                     "predicted": int(p), "p_phish": round(float(pr), 3)})

    deep = pd.concat([
        pd.read_csv(os.path.join(ROOT, "additional_legitimate_urls.csv")),
        pd.read_csv(os.path.join(ROOT, "additional_opensource_urls.csv")),
    ])["url"].dropna().astype(str).drop_duplicates().tolist()
    pred3, proba3 = _predict(deep, model, tld_lookup, char_lookup)
    for u, p, pr in zip(deep, pred3, proba3):
        rows.append({"source": "real_deeplinks", "url": u, "expected": 0,
                     "predicted": int(p), "p_phish": round(float(pr), 3)})

    results = pd.DataFrame(rows)
    results["correct"] = results["predicted"] == results["expected"]
    out_path = os.path.join(outputs_dir, "batch_eval_results.csv")
    results.to_csv(out_path, index=False)

    results["hard_phishing"] = results["p_phish"] >= t_phish
    results["flagged_any"] = results["p_phish"] >= t_unc
    summary = results.groupby("source").agg(
        n=("correct", "size"),
        fp_rate_at_0_5=("predicted", "mean"),
        phishing_verdict_rate=("hard_phishing", "mean"),
        uncertain_or_phishing=("flagged_any", "mean"),
    ).round(4)
    print(f"Tuned thresholds: phishing>={t_phish}, uncertain>={t_unc}")
    print(summary)
    print(f"\nOverall FP rate: {results['predicted'].mean():.4f} "
          f"({results['predicted'].sum()} of {len(results)})")
    print(f"Saved: {out_path}")

    fps = results[results["predicted"] == 1].sort_values("p_phish", ascending=False)
    print(f"\nSample false positives ({len(fps)} total):")
    print(fps[["source", "url", "p_phish"]].head(25).to_string(index=False))


if __name__ == "__main__":
    main()
