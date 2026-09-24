"""
Harvest DATED phishing URLs from public threat feeds, for training with a
time-based split (Model_Comparison_DT_RF.ipynb cell 4).

Why: PhiUSIIL phishing is 2019-2023. Current phishing (OpenPhish 2026) uses
different hosts/paths, so the model missed ~18% of it outright. Adding
recent feed URLs - and TESTING on URLs first seen LATER than anything used
for training - measures and improves real-world detection honestly.

Sources (only the text lists are downloaded; phishing URLs are never visited):
  - Phishing.Database (github.com/Phishing-Database/Phishing.Database):
    its git history keeps every "phishing-links-NEW-today.txt" snapshot,
    so each URL gets the date it was first listed (first_seen).
  - phishunt.io/feed.txt and openphish.com/feed.txt: current feeds, no
    history -> first_seen = today. Re-running this script on later days
    accumulates new OpenPhish URLs with their first-seen date (a genuinely
    future test set).

Noise filter: feeds contain some legitimate sites (e.g. boutique-dofus.fr).
Rows whose registered domain is in the Tranco top 100k are dropped, unless
the feed lists that domain with >= 5 different subdomains (a hosting /
dynamic-DNS platform such as mybluehost.me, where phishing is real).

Output: ../phish_feed_urls.csv (url, first_seen, source). Gitignored like
all *.csv - regenerate with: .venv/Scripts/python notebooks/harvest_phish_feeds.py
"""
import datetime as dt
import json
import os
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "backend"))
from app.reputation import _host, domain_reputation  # noqa: E402

OUT = os.path.join(ROOT, "phish_feed_urls.csv")
CACHE = os.path.join(ROOT, "outputs", "feed_cache")
REPO = "Phishing-Database/Phishing.Database"
FILE = "phishing-links-NEW-today.txt"
SINCE = "2024-07-01"          # oldest snapshot to fetch
NOISE_RANK = 100_000
PLATFORM_MIN_HOSTS = 5
UA = "Mozilla/5.0 (FYP phishing-research harvester)"


def get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def list_commits():
    """Last commit of each day touching FILE, newest first -> {date: sha}."""
    path = os.path.join(CACHE, "commits.json")
    if os.path.exists(path):
        return json.load(open(path))
    per_day, page = {}, 1
    while True:
        d = json.loads(get(f"https://api.github.com/repos/{REPO}/commits"
                           f"?path={FILE}&per_page=100&page={page}"))
        if not d:
            break
        for c in d:
            day = c["commit"]["committer"]["date"][:10]
            per_day.setdefault(day, c["sha"])  # newest-first -> last commit of the day
        if d[-1]["commit"]["committer"]["date"][:10] < SINCE:
            break
        page += 1
    json.dump(per_day, open(path, "w"))
    return per_day


def snapshot(day_sha):
    day, sha = day_sha
    path = os.path.join(CACHE, f"{day}.txt")
    if not os.path.exists(path):
        txt = get(f"https://raw.githubusercontent.com/{REPO}/{sha}/{FILE}")
        open(path, "w", encoding="utf-8").write(txt)
    lines = open(path, encoding="utf-8").read().splitlines()
    return [(u.strip(), day) for u in lines if u.strip().startswith("http")]


def main():
    os.makedirs(CACHE, exist_ok=True)
    today = dt.date.today().isoformat()
    commits = {d: s for d, s in list_commits().items() if d >= SINCE}
    print(f"Phishing.Database: {len(commits)} daily snapshots "
          f"({min(commits)} .. {max(commits)})")
    with ThreadPoolExecutor(max_workers=12) as ex:
        rows = [(u, d, "phishing_database") for snap in ex.map(snapshot, sorted(commits.items()))
                for u, d in snap]

    for name, url in [("phishunt", "https://phishunt.io/feed.txt"),
                      ("openphish", "https://openphish.com/feed.txt")]:
        try:
            feed = [u.strip() for u in get(url).splitlines() if u.strip().startswith("http")]
            rows += [(u, today, name) for u in feed]
            print(f"{name}: {len(feed)} URLs ({today})")
        except Exception as e:
            print(f"{name}: fetch failed ({e})")

    new = pd.DataFrame(rows, columns=["url", "first_seen", "source"])
    if os.path.exists(OUT):  # keep first-seen dates from earlier runs
        new = pd.concat([pd.read_csv(OUT), new], ignore_index=True)
    df = new.sort_values("first_seen").drop_duplicates("url", keep="first")

    # A popular domain listed with many DIFFERENT subdomains is a hosting /
    # dynamic-DNS platform (abc.mybluehost.me, xyz.blogspot.fi) -> real
    # phishing, keep. A popular domain with few hosts is a mislisted or
    # briefly-compromised legitimate site -> drop as label noise.
    rep = df.url.apply(lambda u: domain_reputation(u, max_rank=NOISE_RANK))
    df["_dom"] = [r["domain"] for r in rep]
    df["_host"] = df.url.apply(_host)
    reputable = pd.Series([r["reputable"] for r in rep], index=df.index)
    hosts = df[reputable].groupby("_dom")["_host"].nunique()
    platforms = set(hosts[hosts >= PLATFORM_MIN_HOSTS].index)
    is_noise = reputable & ~df["_dom"].isin(platforms)
    print(f"Kept {int((reputable & ~is_noise).sum())} rows on {len(platforms)} popular domains "
          f"used as hosting platforms (>= {PLATFORM_MIN_HOSTS} subdomains), top: "
          f"{', '.join(hosts[hosts >= PLATFORM_MIN_HOSTS].sort_values(ascending=False).index[:25])}")
    print(f"Dropped {int(is_noise.sum())} rows on other Tranco top-{NOISE_RANK:,} domains "
          f"(e.g. {', '.join(df[is_noise].url.head(3))})")
    df = df[~is_noise].drop(columns=["_dom", "_host"])

    df.to_csv(OUT, index=False)
    print(f"Saved {len(df):,} unique phishing URLs -> {OUT}")
    print(df.groupby([df.first_seen.str[:7], "source"]).size().unstack(fill_value=0).to_string())


if __name__ == "__main__":
    main()
