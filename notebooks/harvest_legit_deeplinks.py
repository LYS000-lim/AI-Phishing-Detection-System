"""
Harvest REAL legitimate deep-link URLs (with paths) from the public
sitemaps of popular websites, to fix PhiUSIIL's training bias.

Why: PhiUSIIL's legitimate class is 100% bare homepages, so the model
learned "has a path / query / is long = phishing". Real websites publish
their real page URLs in sitemap.xml (linked from robots.txt), which gives
genuine deep links without hand-writing them.

Domains: Tranco/top-1m ranks 5,001-100,000, EXCLUDING every domain used by
the evaluation sets (top-1m top 5,000 + tranco_legitimate.csv used by
batch_eval.py, additional_*_urls.csv and fp_category_tests.py), so later
evaluation stays on unseen domains.

Output: ../legit_deeplinks_sitemaps.csv  (URL, label=1, domain)
        label uses PhiUSIIL's RAW convention (1 = legitimate), the same as
        legit_augmentation.csv - the training notebook flips it later.

Run:  python harvest_legit_deeplinks.py   (from notebooks/, ~5-10 min)
"""
import csv
import gzip
import os
import random
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))

RANDOM_STATE = 42
N_DOMAINS = 4000          # domains to try
PER_DOMAIN = 12           # max URLs kept per domain
MAX_BYTES = 3_000_000     # cap per sitemap download
TIMEOUT = 8
UA = "Mozilla/5.0 (PhishGuard-FYP dataset builder; academic research)"
OUT = os.path.join(ROOT, "legit_deeplinks_sitemaps.csv")

_LOC = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)


def _host(u):
    u = u.strip()
    if "//" not in u:
        u = "http://" + u
    h = (urlparse(u).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def excluded_domains():
    ex = set()
    with open(os.path.join(ROOT, "top-1m.csv"), encoding="utf-8") as fh:
        for i, row in enumerate(csv.reader(fh)):
            if i >= 5000:
                break
            ex.add(row[1].lower())
    for name, col in [("tranco_legitimate.csv", "url"),
                      ("additional_legitimate_urls.csv", "url"),
                      ("additional_opensource_urls.csv", "url")]:
        with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                ex.add(_host(row[col]))
    try:
        from tests.fp_category_tests import TEST_CASES  # noqa: E402
        for cases in TEST_CASES.values():
            for case in cases:
                ex.add(_host(case[0] if isinstance(case, (list, tuple)) else case))
    except Exception as exc:  # the test file is optional here
        print("warning: could not read fp_category_tests domains:", exc)
    return ex


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = r.read(MAX_BYTES)
    if url.endswith(".gz") or data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except Exception:
            return ""
    return data.decode("utf-8", "ignore")


def harvest(domain, rng):
    sitemaps = []
    try:
        robots = fetch(f"https://{domain}/robots.txt")
        sitemaps = [l.split(":", 1)[1].strip() for l in robots.splitlines()
                    if l.lower().startswith("sitemap:")]
    except Exception:
        pass
    if not sitemaps:
        sitemaps = [f"https://{domain}/sitemap.xml"]

    urls = []
    for sm in sitemaps[:2]:
        try:
            body = fetch(sm)
        except Exception:
            continue
        locs = _LOC.findall(body)
        if "<sitemapindex" in body.lower():
            # Follow up to 2 child sitemaps
            for child in rng.sample(locs, min(2, len(locs))):
                try:
                    urls += _LOC.findall(fetch(child))
                except Exception:
                    pass
        else:
            urls += locs
        if len(urls) >= 200:
            break

    keep = []
    for u in urls:
        u = u.replace("&amp;", "&").strip()
        if not u.startswith(("http://", "https://")) or len(u) > 300:
            continue
        h = _host(u)
        if not (h == domain or h.endswith("." + domain)):
            continue  # only the site's own pages
        p = urlparse(u)
        if p.path in ("", "/") and not p.query:
            continue  # homepages are already covered by PhiUSIIL
        if re.search(r"\.(xml|gz|jpg|jpeg|png|gif|pdf|mp4|webp)$", p.path, re.I):
            continue
        keep.append(u)
    keep = list(dict.fromkeys(keep))
    return rng.sample(keep, min(PER_DOMAIN, len(keep)))


def main():
    ex = excluded_domains()
    with open(os.path.join(ROOT, "top-1m.csv"), encoding="utf-8") as fh:
        pool = [row[1].lower() for i, row in enumerate(csv.reader(fh))
                if 5000 <= i < 100_000]
    pool = [d for d in pool if d not in ex]
    rng = random.Random(RANDOM_STATE)
    domains = rng.sample(pool, N_DOMAINS)
    print(f"Trying {len(domains)} domains ({len(ex)} evaluation domains excluded)")

    rows, ok = [], 0
    with ThreadPoolExecutor(max_workers=48) as pool_ex:
        futs = {pool_ex.submit(harvest, d, random.Random(hash(d) & 0xffff)): d for d in domains}
        for i, f in enumerate(as_completed(futs), 1):
            d = futs[f]
            try:
                got = f.result()
            except Exception:
                got = []
            if got:
                ok += 1
                rows += [{"URL": u, "label": 1, "domain": d} for u in got]
            if i % 250 == 0:
                print(f"  {i}/{len(domains)} domains, {ok} with sitemaps, {len(rows)} URLs")

    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["URL", "label", "domain"])
        w.writeheader()
        w.writerows(rows)
    print(f"Saved {len(rows)} URLs from {ok} domains -> {OUT}")


if __name__ == "__main__":
    main()
