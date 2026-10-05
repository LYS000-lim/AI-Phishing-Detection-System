"""
5-fold stratified cross-validation of the Decision Tree and Random Forest
on the TRAINING split only (validation/test/future rows are never touched).

The data preparation is not re-implemented: cells 1-6 of
Model_Comparison_DT_RF.ipynb are executed as-is, so the training split,
lookup tables and labels are exactly the ones the deployed model used.
joblib.dump is disabled while they run, so the deployed lookup files in
outputs/ are not overwritten. Hyperparameters and sample weights are the
same as notebook cells 8-9.

Run from the repository root:  .venv/Scripts/python notebooks/cross_validation.py
Saves: outputs/cv_results.json, outputs/cv_results.md
"""
import json
import os
import platform
import time
from datetime import date

import joblib
import nbformat
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold
from sklearn.tree import DecisionTreeClassifier

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "outputs")
N_SPLITS = 5
RANDOM_STATE = 42
AUG_WEIGHT, HARVEST_WEIGHT, FEED_WEIGHT = 10, 2, 1.0   # notebook cell 8

# ---------------------------------------------------------------------------
# 1. Rebuild the notebook's training data (cells 1-6, lookups not saved)
# ---------------------------------------------------------------------------
t0 = time.time()
os.chdir(HERE)                              # notebook paths are relative ("../")
nb = nbformat.read("Model_Comparison_DT_RF.ipynb", as_version=4)
ns = {}
_real_dump = joblib.dump
joblib.dump = lambda *a, **k: None
try:
    for cell in nb.cells[1:7]:
        exec(cell.source, ns)
finally:
    joblib.dump = _real_dump

df, y = ns["df"], ns["y"]
tr = (df["_split"] == "train").values
src = df["_src"].values[tr]
urls = df.loc[tr, "URL"].astype(str)
print(f"Training split: {tr.sum():,} rows. Extracting features...")
X = np.array([[f[n] for n in ns["URL_ONLY_FEATURES"]]
              for f in (ns["compute_features"](u, ns["tld_lookup"], ns["char_lookup"]) for u in urls)],
             dtype=float)
y_tr = y.values[tr].astype(int)
w = np.select([src == "aug", src == "harvest", src == "feed"],
              [AUG_WEIGHT, HARVEST_WEIGHT, FEED_WEIGHT], 1.0)
prep_seconds = time.time() - t0
print(f"Features ready: {X.shape} in {prep_seconds:.0f}s")

# ---------------------------------------------------------------------------
# 2. Cross-validation
# ---------------------------------------------------------------------------
MODELS = {
    "DecisionTree": lambda: DecisionTreeClassifier(
        max_depth=12, min_samples_leaf=5, random_state=RANDOM_STATE),
    "RandomForest": lambda: RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_leaf=2, n_jobs=-1, random_state=RANDOM_STATE),
}
skf = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)
results = {name: [] for name in MODELS}
for fold, (fit_idx, val_idx) in enumerate(skf.split(X, y_tr), start=1):
    for name, make in MODELS.items():
        model = make()
        t = time.time()
        model.fit(X[fit_idx], y_tr[fit_idx], sample_weight=w[fit_idx])
        fit_s = time.time() - t
        pred = model.predict(X[val_idx])
        row = {
            "fold": fold,
            "accuracy": accuracy_score(y_tr[val_idx], pred),
            "precision": precision_score(y_tr[val_idx], pred, pos_label=1),
            "recall": recall_score(y_tr[val_idx], pred, pos_label=1),
            "f1": f1_score(y_tr[val_idx], pred, pos_label=1),
            "fit_seconds": round(fit_s, 1),
            "n_fit": int(len(fit_idx)), "n_val": int(len(val_idx)),
        }
        results[name].append(row)
        print(f"fold {fold} {name:12s} acc={row['accuracy']:.4f} prec={row['precision']:.4f} "
              f"rec={row['recall']:.4f} f1={row['f1']:.4f} ({fit_s:.0f}s)")

METRICS = ["accuracy", "precision", "recall", "f1"]
summary = {
    name: {m: {"mean": float(np.mean([r[m] for r in rows])),
               "std": float(np.std([r[m] for r in rows], ddof=1))} for m in METRICS}
    for name, rows in results.items()
}
total_seconds = time.time() - t0
NOTES = [
    "The training split is rebuilt from the current data files. The deployed model "
    "(trained 2026-09-24) reported n_train = 237,212; phish_feed_urls.csv was refreshed on "
    f"2026-09-27, so the rebuilt split has {int(tr.sum()):,} rows (a difference of "
    f"{abs(237_212 - int(tr.sum())):,} rows).",
    "CV scores are expected to be slightly lower than the headline test-set scores: the "
    "training split also contains recent feed phishing and harvested deep links, which are "
    "harder than PhiUSIIL, while the headline test set is PhiUSIIL + curated rows only.",
]

blob = {
    "date": date.today().isoformat(),
    "method": f"{N_SPLITS}-fold StratifiedKFold(shuffle=True, random_state={RANDOM_STATE}) "
              "on the training split only",
    "positive_class": "Phishing (1)",
    "n_train_rows": int(tr.sum()),
    "class_counts": {"legitimate_0": int((y_tr == 0).sum()), "phishing_1": int((y_tr == 1).sum())},
    "n_features": int(X.shape[1]),
    "sample_weights": {"curated_aug": AUG_WEIGHT, "harvested_deeplinks": HARVEST_WEIGHT,
                       "feed": FEED_WEIGHT, "phiusiil": 1.0},
    "hyperparameters": {"DecisionTree": "max_depth=12, min_samples_leaf=5, random_state=42",
                        "RandomForest": "n_estimators=200, max_depth=20, min_samples_leaf=2, "
                                        "n_jobs=-1, random_state=42"},
    "folds": results,
    "summary": summary,
    "notes": NOTES,
    "runtime_seconds": {"data_prep_and_features": round(prep_seconds, 1),
                        "total": round(total_seconds, 1)},
    "environment": {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
                    "cpu_count": os.cpu_count()},
}
with open(os.path.join(OUT, "cv_results.json"), "w", encoding="utf-8") as fh:
    json.dump(blob, fh, indent=2)

lines = [
    "# 5-Fold Stratified Cross-Validation (training split only)", "",
    f"- Date: {blob['date']}",
    f"- Method: {blob['method']}",
    f"- Rows: {blob['n_train_rows']:,} (legitimate {blob['class_counts']['legitimate_0']:,}, "
    f"phishing {blob['class_counts']['phishing_1']:,}); {blob['n_features']} URL features",
    "- Sample weights as in training: curated augmentation x10, harvested deep links x2, feed x1, PhiUSIIL x1",
    "- Metrics are for the phishing class (positive = 1) at the default 0.5 cut-off, unweighted",
    f"- Runtime: data preparation + feature extraction {prep_seconds / 60:.1f} min, "
    f"total {total_seconds / 60:.1f} min (Python {blob['environment']['python']}, "
    f"scikit-learn {sklearn.__version__}, {os.cpu_count()} CPU threads)",
    *[f"- Note: {n}" for n in NOTES], "",
]
for name, rows in results.items():
    lines += [f"## {name} ({blob['hyperparameters'][name]})", "",
              "| Fold | Accuracy | Precision | Recall | F1-score | Fit time (s) |",
              "|---|---|---|---|---|---|"]
    lines += [f"| {r['fold']} | {r['accuracy']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} | "
              f"{r['f1']:.4f} | {r['fit_seconds']} |" for r in rows]
    s = summary[name]
    lines += ["| **Mean ± SD** | " + " | ".join(
        f"**{s[m]['mean']:.4f} ± {s[m]['std']:.4f}**" for m in METRICS) + " | |", ""]
lines += ["## Summary", "", "| Model | Accuracy | Precision | Recall | F1-score |", "|---|---|---|---|---|"]
for name in results:
    s = summary[name]
    lines.append(f"| {name} | " + " | ".join(f"{s[m]['mean']:.4f} ± {s[m]['std']:.4f}" for m in METRICS) + " |")
with open(os.path.join(OUT, "cv_results.md"), "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
print("\n".join(lines))
