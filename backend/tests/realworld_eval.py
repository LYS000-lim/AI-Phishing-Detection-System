"""
Real-world evaluation of the FULL deployed pipeline on realworld_eval_set.csv
(build it with build_realworld_set.py): live legitimate login/account/
payment pages vs. current OpenPhish phishing URLs.

Compares three stages, so the report can show what each layer contributes:
  model        - ML model + tuned thresholds only
  +allowlist   - curated trusted-domain allowlist first (skips the model)
  +reputation  - deployed system: allowlist, model, then the domain
                 reputation cap (reputable domain -> at most "suspicious")

Also sweeps the reputation rank cut-off, and measures how much PhiUSIIL
phishing sits on domains the reputation layer would treat as reputable.

If phish_feed_urls.csv exists (notebooks/harvest_phish_feeds.py), its 2026
phishunt URLs are added as a second phishing source. Training only uses feed
URLs first seen before 2026, so both phishing sources are a time-based test.
"per campaign" rates count each domain/host group once, so one large
campaign (e.g. 12 URLs on ~primeli3/admin) cannot dominate the result.

Run: python backend/tests/realworld_eval.py
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))

import pandas as pd  # noqa: E402

from app.allowlist import is_trusted  # noqa: E402
from app.features import extract_features, feature_vector  # noqa: E402
from app.ml_state import classify_vec  # noqa: E402
from app.reputation import (  # noqa: E402
    MAX_RANK, _extract_icann, _host, domain_reputation, is_user_content_host,
)

pd.set_option("display.width", 200)
pd.set_option("display.max_columns", None)
CUTOFFS = [50_000, 100_000, 250_000, 500_000, 1_000_000]


def verdicts(url):
    v = classify_vec(feature_vector(url), extract_features(url))
    rep = domain_reputation(url, max_rank=1_000_000)
    return {
        "p_phish": round(v["p_phish"], 3),
        "model": v["prediction"],
        "trusted": is_trusted(url),
        "rank": rep["rank"] if rep["reputable"] else None,  # None if not rankable/platform
    }


def group(u):
    """Campaign key: registered domain, or full host on shared hosting."""
    h = _host(u)
    if not h:
        return ""
    return h if is_user_content_host(u) else (_extract_icann(h).top_domain_under_public_suffix or h)


def system(row, cutoff, use_allowlist=True, use_rep=True):
    if use_allowlist and row["trusted"]:
        return "legitimate"
    if use_rep and row["model"] == "phishing" and row["rank"] is not None and row["rank"] <= cutoff:
        return "uncertain"
    return row["model"]


def summarise(df, col):
    legit, phish = df[df.label == 0], df[df.label == 1]
    per_group = phish.assign(hit=phish[col] == "phishing").groupby("group")["hit"].mean()
    return {
        "legit_called_PHISHING": f"{(legit[col] == 'phishing').mean():.1%}",
        "legit_suspicious": f"{(legit[col] == 'uncertain').mean():.1%}",
        "phish_called_PHISHING": f"{(phish[col] == 'phishing').mean():.1%}",
        "phish_any_warning": f"{(phish[col] != 'legitimate').mean():.1%}",
        "phish_PHISHING_per_campaign": f"{per_group.mean():.1%}",
    }


def main():
    df = pd.read_csv(os.path.join(ROOT, "realworld_eval_set.csv"))
    feed_csv = os.path.join(ROOT, "phish_feed_urls.csv")
    if os.path.exists(feed_csv):
        feed = pd.read_csv(feed_csv)
        feed = feed[(feed.first_seen >= "2026-01-01") & (feed.source == "phishunt")
                    & ~feed.url.isin(set(df.url))]
        df = pd.concat([df, pd.DataFrame({
            "url": feed.url, "label": 1, "category": "phishunt_feed", "source": "phishunt",
            "status": "", "fetched_on": feed.first_seen})], ignore_index=True)
    df["group"] = df.url.map(group)
    print(f"Set: {int((df.label == 0).sum())} legitimate, {int((df.label == 1).sum())} phishing "
          f"in {df[df.label == 1].group.nunique()} campaigns (fetched {df.fetched_on.iloc[0]})\n")
    df = pd.concat([df, pd.DataFrame([verdicts(u) for u in df.url])], axis=1)

    df["s_model"] = df.apply(lambda r: system(r, 0, False, False), axis=1)
    df["s_allow"] = df.apply(lambda r: system(r, 0, True, False), axis=1)
    rows = {"model only": summarise(df, "s_model"), "+allowlist": summarise(df, "s_allow")}
    for c in CUTOFFS:
        df[f"s_{c}"] = df.apply(lambda r: system(r, c), axis=1)
        rows[f"+reputation top {c:,}"] = summarise(df, f"s_{c}")
    print(pd.DataFrame(rows).T.to_string(), "\n")

    col = f"s_{MAX_RANK}"
    for cat in sorted(df[df.label == 1].category.unique()):
        sub = df[(df.label == 0) | (df.category == cat)]
        print(f"Deployed system, phishing source {cat}:", summarise(sub, col))
    print()
    print(f"Deployed cut-off (top {MAX_RANK:,}) by category:")
    by = df.groupby(["label", "category"])[col].value_counts().unstack(fill_value=0)
    print(by.to_string(), "\n")

    bad = df[(df.label == 0) & (df[col] != "legitimate")]
    print("Legitimate pages still warned about:")
    print(bad[["url", "p_phish", col, "rank"]].to_string(index=False), "\n")
    missed = df[(df.label == 1) & (df[col] != "phishing")]
    print(f"Phishing not given a hard PHISHING verdict: {len(missed)}")
    print(missed[["url", "p_phish", col, "rank"]].head(25).to_string(index=False), "\n")

    # How much training-set phishing sits on 'reputable' domains (model-
    # independent: this is the share the cap COULD soften if flagged).
    phi = pd.read_csv(os.path.join(ROOT, "PhiUSIIL_Phishing_URL_Dataset.csv"), usecols=["URL", "label"])
    phi = phi[phi.label == 0].sample(20_000, random_state=42)  # raw label 0 = phishing
    ranks = [domain_reputation(u, max_rank=1_000_000)["rank"] if domain_reputation(u, 1_000_000)["reputable"] else None
             for u in phi.URL]
    s = pd.Series(ranks, dtype="float")
    print("PhiUSIIL phishing (20k sample) on a reputable domain:")
    for c in CUTOFFS:
        print(f"  top {c:>9,}: {(s <= c).mean():.2%}")
    df.to_csv(os.path.join(ROOT, "outputs", "realworld_eval_results.csv"), index=False)


if __name__ == "__main__":
    main()
