"""
Pre-demonstration check of the URLs a person is most likely to type into
the scanner: well-known sites in every input form (with and without
https:// or www.), academic and documentation links, Malaysian banks,
universities and government sites, and phishing patterns (typosquats,
look-alike characters, punycode, brand and Malaysian-agency scams, IP
hosts, free hosting), cloud-document and short links, and redirect links.
Each URL goes through the same steps as POST /api/scan: the URL
validator, then pipeline.evaluate - redirect unwrapping, the trusted
allowlist, the model with the thresholds and post-model rules
(ml_state.classify_vec) and the live page check, which opens Suspicious
pages over the network (set PHISHGUARD_PAGE_CHECK=0 to run offline).

Not a pytest file (like fp_category_tests.py): it prints a table and lists
every URL whose verdict is outside the accepted set.

Run: .venv/Scripts/python backend/tests/viva_url_checks.py
"""
import os
import sys
import warnings

warnings.filterwarnings("ignore")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))

from app.pipeline import evaluate  # noqa: E402
from app.schemas import _validate_url  # noqa: E402

SAFE = {"trusted", "legitimate"}            # what a genuine site should get
WARN = {"uncertain", "phishing"}            # any warning
PHISH = {"phishing"}
SUSPICIOUS = {"uncertain"}

CASES = [
    # (group, url, accepted verdicts)
    ("Typed without https://", "google.com", SAFE),
    ("Typed without https://", "inti.edu.my", SAFE),
    ("Typed without https://", "newinti.edu.my", SAFE),
    ("Typed without https://", "coventry.ac.uk", SAFE),
    ("Typed without https://", "maybank2u.com.my", SAFE),
    ("Typed without https://", "thestar.com.my", SAFE),
    ("Typed without https://", "mudah.my", SAFE),
    ("Typed without https://", "lowyat.net", SAFE),
    ("Typed without https://", "www.petronas.com", SAFE),
    ("Typed without https://", "www.jpj.gov.my", SAFE),
    ("Well-known site", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", SAFE),
    ("Well-known site", "https://youtu.be/dQw4w9WgXcQ", SAFE),
    ("Well-known site", "https://www.facebook.com/", SAFE),
    ("Well-known site", "https://www.instagram.com/accounts/login/", SAFE),
    ("Well-known site", "https://x.com/", SAFE),
    ("Well-known site", "https://www.amazon.com/dp/B0BSHF7WHW", SAFE),
    ("Well-known site", "https://www.netflix.com/", SAFE),
    ("Well-known site", "https://chatgpt.com/", SAFE),
    ("Well-known site", "https://github.com/shap/shap", SAFE),
    ("Well-known site", "https://en.wikipedia.org/wiki/Phishing", SAFE),
    ("Well-known site", "https://www.speedtest.net/", SAFE),
    ("Academic link", "https://scholar.google.com/scholar?hl=en&q=phishing+detection", SAFE),
    ("Academic link", "https://scholar.google.com.my/scholar?q=explainable+ai", SAFE),
    ("Academic link", "https://ieeexplore.ieee.org/document/9534388", SAFE),
    ("Academic link", "https://link.springer.com/article/10.1007/s10462-020-09922-1", SAFE),
    ("Academic link", "https://www.sciencedirect.com/science/article/pii/S0167404823001426", SAFE),
    ("Academic link", "https://arxiv.org/abs/1705.07874", SAFE),
    ("Academic link", "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset", SAFE),
    ("Academic link", "https://www.researchgate.net/publication/344398012_Phishing_Website_Detection", SAFE),
    ("Academic link", "https://onlinelibrary.wiley.com/doi/full/10.1002/sec.1234", SAFE),
    ("Academic link", "https://dl.acm.org/doi/10.1145/3292500.3330701", SAFE),
    ("Academic link", "https://www.mdpi.com/2079-9292/12/3/456", SAFE),
    ("Academic link", "https://www.semanticscholar.org/paper/A-Unified-Approach-Lundberg-Lee/442e10a3c6640ded9408622005e3c2a8906ce4c2", SAFE),
    ("Academic link", "https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html", SAFE),
    ("Malaysian site", "https://www.maybank2u.com.my/home/m2u/common/login.do", SAFE),
    ("Malaysian site", "https://www.cimbclicks.com.my/clicks/#/", SAFE),
    ("Malaysian site", "https://www.rhb.com.my/", SAFE),
    ("Malaysian site", "https://www.ambank.com.my/", SAFE),
    ("Malaysian site", "https://shopee.com.my/", SAFE),
    ("Malaysian site", "https://www.hasil.gov.my/", SAFE),
    ("Malaysian site", "https://www.kwsp.gov.my/", SAFE),
    ("Malaysian site", "https://www.inti.edu.my/programmes/computing-it/", SAFE),
    # A login page on a site that is not allowlisted keeps a Suspicious
    # warning: login wording is what a phishing page on a hacked site uses.
    ("Login page (Suspicious accepted)", "https://elearning.inti.edu.my/login/index.php", SAFE | SUSPICIOUS),
    ("Login page (Suspicious accepted)", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc", SAFE | SUSPICIOUS),
    ("Cloud document link", "https://intiedumy-my.sharepoint.com/personal/kmoorthy_ksamy_newinti_edu_my/_layouts/15/onedrive.aspx?id=%2Fpersonal%2Fkmoorthy%5Fksamy%5Fnewinti%5Fedu%5Fmy%2FDocuments%2F01%2E%20INTI%20FYP%20April%20August%202026&ga=1", SAFE),
    ("Cloud document link", "https://docs.google.com/forms/d/1S0WEo53BqrTdhQwnCuGZpQvychjlg8kGxibUAPTrv-I/edit#settings", SAFE),
    ("Cloud document link", "https://docs.google.com/forms/d/e/1FAIpQLSfAbCdEfGhIjKlMnOpQrStUvWxYz0123/viewform", SAFE),
    ("Cloud document link", "https://docs.google.com/spreadsheets/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit#gid=0", SAFE),
    ("Cloud document link", "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUvWxYz012345/view", SAFE),
    ("Cloud document link", "https://intiedumy.sharepoint.com/sites/FYP2026/Shared%20Documents/Forms/AllItems.aspx", SAFE),
    ("Cloud document link", "https://forms.office.com/Pages/ResponsePage.aspx?id=DQSIkWdsW0yxEjajBLZtrQAAAAAAAAAAAAMAAJ8xYz1UNDVaQ0hSWTRFNk9BNDJRVTZaUjBOMEo3Ri4u", SAFE),
    ("Cloud document link", "https://teams.microsoft.com/l/meetup-join/19%3ameeting_ZjE2YTk0%40thread.v2/0?context=%7b%22Tid%22%3a%2212345%22%7d", SAFE),
    ("Cloud document link", "https://www.dropbox.com/scl/fi/abc123def456/report.pdf?rlkey=xyz789&dl=0", SAFE),
    ("Cloud document link", "https://shap.readthedocs.io/en/latest/", SAFE),
    ("Lure on a shared service", "https://intiedumy-my.sharepoint.com/personal/x/_layouts/15/onedrive.aspx?id=/personal/x/Documents/paypal-verify-account.html", WARN),
    ("Lure on a shared service", "https://docs.google.com/forms/d/e/1FAIpQLSeX/viewform?usp=microsoft-office365-password-reset", WARN),
    ("Short link (Suspicious)", "https://bit.ly/3xYzAbC", SUSPICIOUS),
    ("Short link (Suspicious)", "https://forms.gle/AbCdEfGhIjKlMnOp9", SUSPICIOUS),
    ("Short link (Suspicious)", "https://tinyurl.com/2p8h9xyz", SUSPICIOUS),
    ("Redirect link", "https://www.google.com/url?q=https://evil-login.xyz/verify", WARN),
    ("Redirect link", "https://www.facebook.com/l.php?u=https%3A%2F%2Fpaypa1-secure.top%2Flogin", PHISH),
    ("Redirect link", "https://apc01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.inti.edu.my%2F&data=05%7C02&reserved=0", SAFE),
    ("Redirect link", "https://www.google.com/url?sa=t&url=https://www.youtube.com/watch?v=dQw4w9WgXcQ", SAFE),
    ("Typosquat / look-alike", "https://www.g00gle.com", PHISH),
    ("Typosquat / look-alike", "https://www.paypa1.com/signin", PHISH),
    ("Typosquat / look-alike", "https://www.micros0ft.com", PHISH),
    ("Typosquat / look-alike", "https://www.faceb00k.com/login", PHISH),
    ("Typosquat / look-alike", "https://www.arnazon.com", PHISH),
    ("Typosquat / look-alike", "https://www.netfl1x.com/login", PHISH),
    ("Typosquat / look-alike", "https://xn--pypal-4ve.com/", PHISH),
    ("Typosquat / look-alike", "https://www.gooogle.com", WARN),
    ("Typosquat / look-alike", "https://www.linkedln.com/login", WARN),
    ("Typosquat / look-alike", "https://www.paypai.com", WARN),
    ("Typosquat / look-alike", "https://www.whatsap.com", WARN),
    ("Brand / Malaysian scam", "http://maybank2u-secure-login.com/m2u/login", WARN),
    ("Brand / Malaysian scam", "https://www.maybank2u.com.my.verify-account.xyz/", WARN),
    ("Brand / Malaysian scam", "http://cimbclicks-my.com/login", WARN),
    ("Brand / Malaysian scam", "https://hasil-gov-my.com/refund", WARN),
    ("Brand / Malaysian scam", "https://jpj-saman-online.com/bayar", WARN),
    ("Brand / Malaysian scam", "https://kwsp-pengeluaran-i-akaun.com/", WARN),
    ("Brand / Malaysian scam", "https://poslaju-redelivery.top/pay", WARN),
    ("Brand / Malaysian scam", "http://tngdigital-ewallet-reward.com/claim", WARN),
    ("Brand / Malaysian scam", "https://shopee-my-refund.com/claim", WARN),
    ("Brand / Malaysian scam", "https://dhl-parcel-customs-fee.com/pay", WARN),
    ("Brand / Malaysian scam", "https://petronas-50th-anniversary-gift.com/", WARN),
    ("Phishing pattern", "http://paypa1-secure-login.win/verify.php?id=aGVsbG8=&acct=443", PHISH),
    ("Phishing pattern", "http://45.33.32.156/paypal/login", PHISH),
    ("Phishing pattern", "http://paypal.com.account.verify.login.secure-update.xyz/", PHISH),
    ("Phishing pattern", "http://www.google.com@evil-phish.xyz/login", PHISH),
    ("Phishing pattern", "https://chase.trustbnkdirect.com/twnmy=", PHISH),
    ("Phishing pattern", "http://free-iphone-15-giveaway.win/claim", PHISH),
    ("Phishing pattern", "http://windows-defender-security-alert.com/call-support", PHISH),
    ("Phishing pattern", "https://login-microsoftonline.com-secure.auth-verify.top/common/oauth2/authorize", PHISH),
    ("Phishing pattern", "https://microsoft-account-verify.netlify.app/login", PHISH),
    ("Phishing pattern", "https://officehome.westus.cloudapp.azure.com", PHISH),
    ("Phishing pattern", "http://outlookofficeup.netlify.com", PHISH),
    ("Phishing pattern", "https://sites.google.com/view/office365-login-secure/home", PHISH),
    ("Phishing pattern", "http://paypal-login-security.test", PHISH),
    ("Phishing pattern", "http://amazon-account-verification.test", PHISH),
]


def verdict(url):
    try:
        result = evaluate(_validate_url(url))
    except ValueError:
        return "rejected", ""
    if result["trusted"]:
        return "trusted", ""
    v = result["verdict"]
    note = v.get("uncertain_reason") or v.get("legit_reason") or v.get("escalated_by") or ""
    return v["prediction"], f"{v['p_phish']:.2f} {note}".strip()


def main():
    shown = {"trusted": "Trusted Website", "legitimate": "Legitimate", "uncertain": "Suspicious",
             "phishing": "Phishing", "rejected": "Rejected"}
    groups, failures = {}, []
    for group, url, accepted in CASES:
        got, note = verdict(url)
        ok = got in accepted
        groups.setdefault(group, [0, 0])
        groups[group][0] += ok
        groups[group][1] += 1
        if not ok:
            failures.append((group, url, shown[got], note))
    print(f"{'Group':40s} {'as expected':>12s}")
    for group, (ok, n) in groups.items():
        print(f"{group:40s} {ok:>5d} / {n:<5d}")
    total_ok = sum(v[0] for v in groups.values())
    print(f"\nTotal: {total_ok} / {len(CASES)} as expected")
    if failures:
        print("\nNot as expected:")
        for group, url, got, note in failures:
            print(f"  [{group}] {url} -> {got} ({note})")


if __name__ == "__main__":
    main()
