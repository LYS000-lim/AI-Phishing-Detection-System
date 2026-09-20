"""
Manual categorized URL test suite for the RandomForest phishing model.

Covers the URL patterns known to drive false positives/negatives (bare
domain, subdomain, path, query string, hyphens, digits, unusual TLD, HTTP,
IP, typosquat) so a retrain's impact can be checked per-category, not just
on a handful of anecdotal URLs.

Run: python backend/tests/fp_category_tests.py
Saves: outputs/manual_test_results.csv (per-URL) + prints per-category summary.
Label convention: 0 = legitimate, 1 = phishing (matches app/features.py).
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))

import joblib
import pandas as pd

from app.features import URL_ONLY_FEATURES, compute_features

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


def main():
    outputs_dir = os.path.join(ROOT, "outputs")
    tld_lookup = joblib.load(os.path.join(outputs_dir, "tld_probability_lookup.joblib"))
    char_lookup = joblib.load(os.path.join(outputs_dir, "char_probability_lookup.joblib"))
    model = joblib.load(os.path.join(outputs_dir, "rf_model.joblib"))

    rows = []
    for category, cases in TEST_CASES.items():
        for url, expected in cases:
            feats = compute_features(url, tld_lookup, char_lookup)
            fv = [[feats[n] for n in URL_ONLY_FEATURES]]
            p_phish = float(model.predict_proba(fv)[0][1])
            pred = int(p_phish >= 0.5)
            rows.append({
                "category": category,
                "url": url,
                "expected": expected,
                "predicted": pred,
                "p_phish": round(p_phish, 3),
                "correct": pred == expected,
            })

    results = pd.DataFrame(rows)
    out_path = os.path.join(outputs_dir, "manual_test_results.csv")
    results.to_csv(out_path, index=False)

    summary = results.groupby("category").agg(
        n=("correct", "size"), accuracy=("correct", "mean")
    ).round(3)
    overall_acc = results["correct"].mean()

    print(summary)
    print(f"\nOverall: {len(results)} URLs, accuracy={overall_acc:.3f}")
    print(f"Saved: {out_path}")

    wrong = results[~results["correct"]]
    if len(wrong):
        print("\nMisclassified:")
        print(wrong[["category", "url", "expected", "predicted", "p_phish"]].to_string(index=False))


if __name__ == "__main__":
    main()
