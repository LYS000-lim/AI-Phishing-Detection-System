"""
Manual categorized URL test suite for the RandomForest phishing model.

Covers the URL patterns known to drive false positives/negatives (bare
domain, subdomain, path, query string, hyphens, digits, unusual TLD, HTTP,
IP, typosquat) so a retrain's impact can be checked per-category, not just
on a handful of anecdotal URLs.

Reports two things per category:
  raw model  - model.predict_proba at the plain 0.5 cut-off (model quality)
  live app   - what users actually see: allowlist -> model with tuned
               thresholds -> reputation cap -> HTTP rule (ml_state.classify_vec)
Quote the live-app numbers for system behaviour; the raw numbers only show
how much the post-model layers are compensating for.

Run: python backend/tests/fp_category_tests.py
Saves: outputs/manual_test_results.csv (per-URL) + prints per-category summary.
Label convention: 0 = legitimate, 1 = phishing (matches app/features.py).
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))

import joblib
import numpy as np
import pandas as pd

from app.allowlist import is_trusted
from app.features import URL_ONLY_FEATURES, compute_features, extract_features, feature_vector
from app.ml_state import PHISH_THRESHOLD, UNCERTAIN_THRESHOLD, classify_vec

TEST_CASES = {
    # NOTE: none of the "legit" URLs below are in app/allowlist.py's
    # TRUSTED_DOMAINS on purpose -- this suite measures the ML model itself.
    # If it used allowlisted domains, the live site's allowlist bypass would
    # make its result meaningless to compare against this file's output.
    "bare_root_legit": [
        ("https://numpy.org", 0),
        ("https://scikit-learn.org", 0),
        ("https://pytorch.org", 0),
        ("https://rust-lang.org", 0),
        ("https://djangoproject.com", 0),
    ],
    "www_root_legit": [
        ("https://www.kernel.org", 0),
        ("https://www.gnu.org", 0),
        ("https://www.eff.org", 0),
    ],
    "subdomain_legit": [
        ("https://docs.python.org", 0),
        ("https://wiki.archlinux.org", 0),
        ("https://blog.rust-lang.org", 0),
        ("https://planet.mozilla.org", 0),
    ],
    "deep_path_legit": [
        ("https://rust-lang.org/learn", 0),
        ("https://docs.djangoproject.com/en/5.0/topics/", 0),
        ("https://wiki.archlinux.org/title/Installation_guide", 0),
    ],
    "query_string_legit": [
        ("https://docs.python.org/3/search.html?q=os.path", 0),
        ("https://djangoproject.com/search/?q=queryset", 0),
    ],
    "hyphen_domain_legit": [
        ("https://coca-cola.com", 0),
        ("https://t-mobile.com", 0),
        ("https://in-n-out.com", 0),
        ("https://7-eleven.com", 0),
    ],
    "digit_tld_legit": [
        ("https://web3.storage", 0),
        ("https://1password.com", 0),
        ("https://37signals.com", 0),
    ],
    "unusual_tld_legit": [
        ("https://vercel.app", 0),
        ("https://netlify.app", 0),
        ("https://web.dev", 0),
        ("https://github.io", 0),
    ],
    "http_legit": [
        ("http://example.com", 0),
        ("http://neverssl.com", 0),
    ],
    "ip_phish": [
        ("http://192.168.0.1/login.php?redirect=%2Fadmin", 1),
        ("http://45.33.32.156/paypal/login", 1),
    ],
    "typosquat_hyphen_phish": [
        ("http://paypa1-secure-login.win/verify.php?id=aGVsbG8=&acct=443", 1),
        ("http://apple-id-verify-account.com/signin", 1),
        ("http://secure-login-paypal.com/update", 1),
    ],
    "brand_in_path_phish": [
        ("http://freehost123.net/paypal/login/verify", 1),
        ("http://bit-secure.xyz/amazon/account/confirm", 1),
    ],
    "obfuscated_phish": [
        ("http://phishy-verify.tk/login?id=aGVsbG8=&redirect=%2F%2Fevil.com", 1),
        ("http://0x4A7D2B1C.xyz/bank/update", 1),
    ],
}


def live_verdict(url):
    """The verdict the website/extension shows for this URL."""
    if is_trusted(url):
        return "legitimate"
    return classify_vec(feature_vector(url), extract_features(url), url)["prediction"]


def main():
    outputs_dir = os.path.join(ROOT, "outputs")
    tld_lookup = joblib.load(os.path.join(outputs_dir, "tld_probability_lookup.joblib"))
    char_lookup = joblib.load(os.path.join(outputs_dir, "char_probability_lookup.joblib"))
    model = joblib.load(os.path.join(outputs_dir, "deployment_model.joblib"))
    print(f"Thresholds: phishing>={PHISH_THRESHOLD}, suspicious>={UNCERTAIN_THRESHOLD}")

    rows = []
    for category, cases in TEST_CASES.items():
        for url, expected in cases:
            feats = compute_features(url, tld_lookup, char_lookup)
            p_phish = float(model.predict_proba([[feats[n] for n in URL_ONLY_FEATURES]])[0][1])
            pred = int(p_phish >= 0.5)
            live = live_verdict(url)
            rows.append({
                "category": category,
                "url": url,
                "expected": expected,
                "predicted": pred,
                "p_phish": round(p_phish, 3),
                "correct": pred == expected,
                "live_verdict": live,
                # Legit: correct only if shown Legitimate. Phishing: correct
                # only if shown Phishing (Suspicious is a warning, not a catch).
                "live_correct": live == ("phishing" if expected == 1 else "legitimate"),
                "live_warned": live != "legitimate",
            })

    results = pd.DataFrame(rows)
    out_path = os.path.join(outputs_dir, "manual_test_results.csv")
    results.to_csv(out_path, index=False)

    summary = results.groupby("category").agg(
        n=("correct", "size"), raw_accuracy=("correct", "mean"),
        live_accuracy=("live_correct", "mean"),
    ).round(3)
    print(summary)

    legit, phish = results[results.expected == 0], results[results.expected == 1]
    print(f"\nRaw model @0.5: {len(results)} URLs, accuracy={results['correct'].mean():.3f}")
    print(f"Live app:       accuracy={results['live_correct'].mean():.3f} | "
          f"legit shown Phishing {int((legit.live_verdict == 'phishing').sum())}/{len(legit)}, "
          f"legit shown Suspicious {int((legit.live_verdict == 'uncertain').sum())}/{len(legit)} | "
          f"phishing shown Phishing {int((phish.live_verdict == 'phishing').sum())}/{len(phish)}, "
          f"any warning {int(phish.live_warned.sum())}/{len(phish)}")
    print(f"Saved: {out_path}")

    wrong = results[~results["live_correct"]]
    if len(wrong):
        print("\nNot shown with the expected verdict in the live app:")
        print(wrong[["category", "url", "expected", "p_phish", "live_verdict"]].to_string(index=False))


if __name__ == "__main__":
    main()
