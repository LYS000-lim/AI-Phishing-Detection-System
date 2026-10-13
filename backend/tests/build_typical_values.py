"""
Builds outputs/feature_typical_values.json: the 10th, 50th and 90th
percentile of every model feature for legitimate and for phishing URLs,
used by the what-if panel in /api/explain ("what would change this
result?"). Medians alone are not enough: for many features both classes
share the same median (e.g. a .com ending), so the panel picks whichever
of the three typical values moves the score most.

Features are recomputed with the app's own extractor (app.features
.extract_features) on a random sample of PhiUSIIL URLs, so the typical
values match what the live model sees.

Run: python backend/tests/build_typical_values.py
Label convention: PhiUSIIL label 1 = legitimate, 0 = phishing.
"""
import json
import os
import sys
import warnings

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))
warnings.filterwarnings("ignore")

import pandas as pd

from app.features import FEATURE_ORDER, extract_features

SAMPLE_PER_CLASS = 20000

df = pd.read_csv(os.path.join(ROOT, "PhiUSIIL_Phishing_URL_Dataset.csv"), usecols=["URL", "label"])
out = {}
for name, label in (("legitimate", 1), ("phishing", 0)):
    urls = df[df.label == label].URL.sample(SAMPLE_PER_CLASS, random_state=42)
    feats = pd.DataFrame([extract_features(u) for u in urls])[FEATURE_ORDER].astype(float)
    out[name] = {
        f: [round(float(feats[f].quantile(q)), 4) for q in (0.1, 0.5, 0.9)]
        for f in FEATURE_ORDER
    }

path = os.path.join(ROOT, "outputs", "feature_typical_values.json")
with open(path, "w") as fh:
    json.dump(out, fh, indent=2)
print(pd.DataFrame({k: {f: v[f] for f in FEATURE_ORDER} for k, v in out.items()}))
print("Saved:", path)
