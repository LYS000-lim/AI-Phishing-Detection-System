"""
Stage-2 model: the URL model's score combined with the domain's age.

The URL model (stage 1, Random Forest on 22 URL features) cannot know how
long a domain has existed. Phishing domains are mostly bought days or weeks
before an attack; genuine websites keep theirs for years. Stage 2 is a
logistic regression with two inputs - the stage-1 score (as log-odds) and
log(1 + domain age in days) - so the final phishing probability is still
produced by machine learning, and each input's effect is one readable
coefficient.

Data (never used to train stage 1, so its scores are honest):
  phishing   phish_feed_urls.csv rows first seen in 2026 (Sept 2026) and the
             OpenPhish + phishunt feeds of 2026-10-16
             (phish_feed_live_2026_10_16.csv); at most 2 URLs per domain
  legitimate realworld_eval_set.csv legitimate rows, deep links of the 30% of
             harvested domains held out of stage-1 training, and homepages
             of 600 Tranco domains ranked 250,001-1,000,000
Domain age is taken at the time a phishing URL was first seen. URLs on
shared hosting (sites.google.com, *.pages.dev ...) and URLs whose domain age
could not be found are left out: stage 2 does not apply to them.

Split: phishing first seen in September -> train; 2026-10-16 -> test.
Legitimate domains: 70% train / 30% test. Thresholds are tuned on
cross-validated training predictions so that legitimate URLs are warned no
more often than by stage 1 alone.

Output: outputs/stage2_model.joblib, outputs/stage2_metrics.json,
        outputs/stage2_set.csv
Run:    .venv/Scripts/python notebooks/train_stage2.py
"""
import json
import os
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import cross_val_predict

warnings.filterwarnings("ignore")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "outputs")
sys.path.insert(0, os.path.join(ROOT, "backend"))
os.environ["PHISHGUARD_PAGE_CHECK"] = "0"

import app.ml_state as ms  # noqa: E402
from app import domain_age  # noqa: E402
from app.features import feature_vector  # noqa: E402
from app.reputation import _extract_icann, _host, is_user_content_host  # noqa: E402
from app.schemas import _validate_url  # noqa: E402

ms.MODEL.n_jobs = 1
LIVE_DATE = "2026-10-16"
SEED = 42


def build_set() -> pd.DataFrame:
    feed = pd.read_csv(os.path.join(ROOT, "phish_feed_urls.csv"))
    feed = feed[feed.first_seen >= "2026-01-01"][["url", "first_seen", "source"]]
    live = pd.read_csv(os.path.join(ROOT, "phish_feed_live_2026_10_16.csv")).assign(first_seen=LIVE_DATE)
    phish = pd.concat([feed, live], ignore_index=True).drop_duplicates("url")

    def group(u):
        h = _host(u)
        return h if is_user_content_host(u) else (_extract_icann(h).top_domain_under_public_suffix or h)

    phish["g"] = phish.url.map(group)
    phish = phish.sample(frac=1, random_state=1).groupby("g").head(2).drop(columns="g").assign(label=1)

    rw = pd.read_csv(os.path.join(ROOT, "realworld_eval_set.csv"))
    harv = pd.read_csv(os.path.join(ROOT, "legit_deeplinks_sitemaps.csv")).drop_duplicates("URL")
    domains = sorted(harv.domain.unique())
    domains = [domains[i] for i in np.random.default_rng(SEED).permutation(len(domains))]
    held = set(domains[int(0.70 * len(domains)):])          # same split as stage-1 training
    harv = harv[harv.domain.isin(held)].groupby("domain").head(3)
    top = pd.read_csv(os.path.join(ROOT, "top-1m.csv"), header=None, names=["rank", "domain"])
    tail = top[top["rank"] > 250_000].sample(600, random_state=7)
    legit = pd.concat([
        pd.DataFrame({"url": rw[rw.label == 0].url, "source": "realworld"}),
        pd.DataFrame({"url": harv.URL, "source": "deeplink_heldout"}),
        pd.DataFrame({"url": "https://" + tail.domain, "source": "tranco_250k_1m"}),
    ], ignore_index=True).drop_duplicates("url").assign(label=0, first_seen=LIVE_DATE)

    rows = []
    for u, label, seen, src in pd.concat([phish, legit])[["url", "label", "first_seen", "source"]].values:
        try:
            v = _validate_url(str(u))
        except ValueError:
            continue
        if is_user_content_host(v):
            continue
        host = _host(v)
        rows.append({"url": v, "label": label, "first_seen": seen, "source": src,
                     "domain": _extract_icann(host).top_domain_under_public_suffix or host})
    df = pd.DataFrame(rows)
    df["stage1"] = [float(ms.MODEL.predict_proba(feature_vector(u))[0][1]) for u in df.url]
    with ThreadPoolExecutor(6) as pool:
        found = dict(zip(sorted(set(df.domain)), pool.map(domain_age.registered, sorted(set(df.domain)))))

    def age(row):
        reg = found.get(row.domain)
        if reg is None:
            return np.nan
        return max((datetime.fromisoformat(row.first_seen).replace(tzinfo=timezone.utc) - reg).days, 0)

    df["age_days"] = df.apply(age, axis=1)
    return df


def features(stage1, age_days) -> np.ndarray:
    p = np.clip(np.asarray(stage1, dtype=float), 1e-4, 1 - 1e-4)
    return np.column_stack([np.log(p / (1 - p)), np.log1p(np.clip(np.asarray(age_days, dtype=float), 0, None))])


def main():
    df = build_set()
    df.to_csv(os.path.join(OUT, "stage2_set.csv"), index=False)
    known = df.dropna(subset=["age_days"]).reset_index(drop=True)
    print("rows with a domain age:", known.label.value_counts().to_dict(),
          "| no age found:", int(df.age_days.isna().sum()))

    rng = np.random.default_rng(0)
    legit_dom = known[known.label == 0].domain.unique()
    test_dom = set(rng.choice(legit_dom, size=int(0.3 * len(legit_dom)), replace=False))
    is_test = np.where(known.label == 1, known.first_seen >= LIVE_DATE, known.domain.isin(test_dom))
    tr, te = known[~is_test], known[is_test]
    X_tr, X_te = features(tr.stage1, tr.age_days), features(te.stage1, te.age_days)

    model = LogisticRegression(max_iter=1000)
    cv_p = cross_val_predict(model, X_tr, tr.label, cv=5, method="predict_proba")[:, 1]
    model.fit(X_tr, tr.label)

    # Thresholds: legitimate URLs may be warned (Suspicious or worse) and
    # called Phishing no more often than by stage 1 alone with its tuned
    # thresholds; among those, take the lowest (most phishing caught).
    legit_tr = tr.label.values == 0
    s1_warn = float((tr.stage1.values[legit_tr] >= ms.UNCERTAIN_THRESHOLD).mean())
    s1_phish = float((tr.stage1.values[legit_tr] >= ms.PHISH_THRESHOLD).mean())
    grid = np.round(np.arange(0.30, 0.99, 0.01), 2)
    warn_t = min(t for t in grid if (cv_p[legit_tr] >= t).mean() <= s1_warn)
    phish_t = min(t for t in grid if t >= warn_t and (cv_p[legit_tr] >= t).mean() <= s1_phish)

    p_te = model.predict_proba(X_te)[:, 1]

    def rates(scores, warn, phish, labels):
        scores, labels = np.asarray(scores), np.asarray(labels)
        return {"phishing_warned": round(float((scores[labels == 1] >= warn).mean()), 4),
                "phishing_called_phishing": round(float((scores[labels == 1] >= phish).mean()), 4),
                "legit_warned": round(float((scores[labels == 0] >= warn).mean()), 4),
                "legit_called_phishing": round(float((scores[labels == 0] >= phish).mean()), 4)}

    metrics = {
        "coefficients": {"stage1_logodds": round(float(model.coef_[0][0]), 4),
                         "log1p_age_days": round(float(model.coef_[0][1]), 4),
                         "intercept": round(float(model.intercept_[0]), 4)},
        "thresholds": {"uncertain": float(warn_t), "phishing": float(phish_t)},
        "train": {"n": tr.label.value_counts().to_dict(), "cv_auc": round(roc_auc_score(tr.label, cv_p), 4)},
        "test": {
            "n": te.label.value_counts().to_dict(),
            "auc_stage1": round(roc_auc_score(te.label, te.stage1), 4),
            "auc_stage2": round(roc_auc_score(te.label, p_te), 4),
            "stage1": rates(te.stage1, ms.UNCERTAIN_THRESHOLD, ms.PHISH_THRESHOLD, te.label),
            "stage2": rates(p_te, warn_t, phish_t, te.label),
        },
    }
    metrics = json.loads(json.dumps(metrics, default=lambda o: int(o) if isinstance(o, np.integer) else str(o)))
    joblib.dump({"model": model, "thresholds": metrics["thresholds"],
                 "features": ["stage1_logodds", "log1p_age_days"], "trained": LIVE_DATE},
                os.path.join(OUT, "stage2_model.joblib"))
    with open(os.path.join(OUT, "stage2_metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=1)
    print(json.dumps(metrics, indent=1))


if __name__ == "__main__":
    main()
