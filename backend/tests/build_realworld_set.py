"""
Build the REAL-WORLD evaluation set used by realworld_eval.py.

Why: PhiUSIIL's legitimate class is almost entirely homepages, so its test
accuracy says nothing about the pages an examiner/user actually worries
about - real login, account, banking, university and payment pages.

- Legitimate: realworld_legit_candidates.txt (hand-picked login/account/
  payment URLs of real organisations). Each is requested once; only URLs
  that respond (anything except DNS failure, 404/410 or 5xx) are kept, so
  every row is a live page. 401/403 count as live (login walls / bot checks).
- Phishing: the OpenPhish community feed (https://openphish.com/feed.txt) -
  recently confirmed phishing URLs. Only the TEXT LIST is downloaded; the
  phishing URLs themselves are never visited.

Output: ../../realworld_eval_set.csv (url, label[0=legit,1=phish], category,
source, status, fetched_on). Re-run to refresh (the phishing feed changes
daily, so record the date in the report).

Run: python backend/tests/build_realworld_set.py
"""
import csv
import datetime as dt
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HERE = os.path.dirname(__file__)
OUT = os.path.join(ROOT, "realworld_eval_set.csv")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
FEED = "https://openphish.com/feed.txt"


def check(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        # The server exists and answered, but blocks scripts (read timeout)
        # or has an incomplete certificate chain that browsers tolerate
        # (e.g. some .edu.my sites) - still a live, real site.
        msg = str(e)
        if "timed out" in msg or "CERTIFICATE_VERIFY_FAILED" in msg:
            return 0
        return None  # DNS failure / connection refused


def main():
    today = dt.date.today().isoformat()
    cands = []
    with open(os.path.join(HERE, "realworld_legit_candidates.txt"), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                cat, url = line.split("\t")
                cands.append((cat, url))

    with ThreadPoolExecutor(max_workers=24) as ex:
        statuses = list(ex.map(lambda c: check(c[1]), cands))

    rows, dropped = [], []
    for (cat, url), st in zip(cands, statuses):
        if st is None or st in (404, 410) or st >= 500:
            dropped.append((st, url))
            continue
        rows.append({"url": url, "label": 0, "category": cat,
                     "source": "curated_live_check", "status": st, "fetched_on": today})
    print(f"Legitimate: kept {len(rows)} of {len(cands)} candidates")
    for st, url in dropped:
        print(f"  dropped ({st}): {url}")

    req = urllib.request.Request(FEED, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        feed = [u.strip() for u in r.read().decode("utf-8", "ignore").splitlines() if u.strip()]
    feed = list(dict.fromkeys(feed))
    for url in feed:
        rows.append({"url": url, "label": 1, "category": "openphish_feed",
                     "source": "openphish", "status": "", "fetched_on": today})
    print(f"Phishing: {len(feed)} URLs from OpenPhish feed ({today})")

    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["url", "label", "category", "source", "status", "fetched_on"])
        w.writeheader()
        w.writerows(rows)
    print("Saved:", OUT)


if __name__ == "__main__":
    main()
