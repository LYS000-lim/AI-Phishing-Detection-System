# False-Negative Analysis: Phishing Shown as Legitimate

**Data.** The real-world set (`realworld_eval_set.csv`) has 300 OpenPhish URLs (fetched 2026-09-23). `backend/tests/realworld_eval.py` adds 878 phishunt URLs first seen in 2026, giving **1,178 phishing URLs** in total. None of these campaigns were used in training.

**False negatives.** Using the evaluation script's pipeline (allowlist, then the model with thresholds 0.89 / 0.73, then the reputation cap), **185 of 1,178 (15.7%)** phishing URLs are shown as Legitimate.

**Correction found during this analysis.** `realworld_eval.py` calls `classify_vec()` without the URL, so it skips the **brand-impersonation rule** and the **HTTP rule**. The live app runs both. Re-scoring the same 1,178 URLs exactly as the live app does:

| Verdict | Evaluation script | Live app |
|---|---|---|
| Phishing | 866 (73.5%) | 903 (76.7%) |
| Suspicious | 127 (10.8%) | 147 (12.5%) |
| Legitimate (false negative) | 185 (15.7%) | 128 (10.9%) |
| Any warning (Phishing or Suspicious) | 84.3% | 89.1% |

So the live app misses **128** phishing URLs, not 185. The other 57 are raised to Suspicious by the brand rule. The analysis below covers all 185; the 'Still missed by live app' column shows which ones the live app still misses.

## 1. Main reason per URL

Each URL gets **one** reason: the first group that applies, checked in order A to E.

| Group | Count | % of the false negatives | Still missed by live app | Median phishing score |
|---|---|---|---|---|
| A. Shared hosting platform or reputable domain | 5 | 2.7% | 3 | 0.58 |
| B. Brand name in hostname (caught by the live app's brand rule) | 55 | 29.7% | 0 | 0.30 |
| C. Short clean domain, no keywords | 71 | 38.4% | 71 | 0.27 |
| D. Very short or no path | 47 | 25.4% | 47 | 0.17 |
| E. Other (longer domain or path that still looks legitimate) | 7 | 3.8% | 7 | 0.60 |
| **Total** | **185** | 100% | **128** | 0.27 |

Group definitions:
- **A.** The host is a shared hosting, free-site, cloud or dynamic-DNS platform where anyone can publish (list in `reputation.py`), or the domain is in the Tranco top 250,000.
- **B.** The hostname contains one of the 75 brands mined from phishing feeds (`brands.py`) on a domain that is not well established.
- **C.** The registered domain name is 12 characters or fewer, with no digits, no hyphens and no credential or financial keywords.
- **D.** The path has at most one segment and there is no query string.
- **E.** Everything else.

## 2. Shared characteristics (a URL can have several)

| Characteristic | Count | % of the false negatives |
|---|---|---|
| Uses HTTPS | 162 | 87.6% |
| No suspicious keywords (login, verify, bank, ...) | 184 | 99.5% |
| No known brand outside its official domain (model feature) | 144 | 77.8% |
| No feed-mined brand in the hostname (brand rule) | 128 | 69.2% |
| No subdomain | 152 | 82.2% |
| Path with 0-1 segments and no query | 151 | 81.6% |
| Hosted on a shared platform | 4 | 2.2% |
| Domain in the Tranco top 250k | 1 | 0.5% |
| Phishing score below 0.50 (clearly legitimate to the model) | 142 | 76.8% |
| Phishing score 0.50 to 0.73 (just under the Suspicious threshold) | 43 | 23.2% |

## 3. Anonymised examples (up to 5 per group)

Domain names are replaced by their length (e.g. `[7-char name].com`) and path segments by their length, except generic words such as `admin`, `login` or `index.php`. Shared-platform domains (e.g. `weebly.com`) are public infrastructure, so they are kept; the user's subdomain is hidden.

### A. Shared hosting platform or reputable domain

| Anonymised URL | Phishing score | Live app |
|---|---|---|
| `http://[1-char name].to/[35]/[6]` | 0.16 | Legitimate |
| `https://[sub11].eu.org` | 0.46 | Suspicious |
| `https://[sub7].[sub6].eu.org` | 0.58 | Suspicious |
| `https://qrco.de/[6]` | 0.67 | Legitimate |
| `https://[sub11].eu.org/[4]` | 0.67 | Legitimate |

### B. Brand name in hostname (caught by the live app's brand rule)

| Anonymised URL | Phishing score | Live app |
|---|---|---|
| `https://[sub8].[3-char name].com.my` | 0.01 | Suspicious |
| `https://[11-char name].org` | 0.02 | Suspicious |
| `https://[14-char name].de` | 0.02 | Suspicious |
| `https://[9-char name].com` | 0.03 | Suspicious |
| `https://[14-char name].com` | 0.03 | Suspicious |

### C. Short clean domain, no keywords

| Anonymised URL | Phishing score | Live app |
|---|---|---|
| `https://[8-char name].at` | 0.02 | Legitimate |
| `https://[12-char name].com.au` | 0.02 | Legitimate |
| `https://[9-char name].org/` | 0.02 | Legitimate |
| `https://[sub3].[5-char name].ai/` | 0.02 | Legitimate |
| `https://[9-char name].com` | 0.03 | Legitimate |

### D. Very short or no path

| Anonymised URL | Phishing score | Live app |
|---|---|---|
| `https://[8-char name].org` | 0.03 | Legitimate |
| `https://[14-char name].com` | 0.03 | Legitimate |
| `https://[14-char name].com` | 0.03 | Legitimate |
| `https://[13-char name].com` | 0.03 | Legitimate |
| `https://[18-char name].com` | 0.04 | Legitimate |

### E. Other (longer domain or path that still looks legitimate)

| Anonymised URL | Phishing score | Live app |
|---|---|---|
| `https://[4-char name].at/[3]/[33]` | 0.24 | Legitimate |
| `https://[9-char name].com/[12]/wp-content/[7]/[14]` | 0.27 | Legitimate |
| `http://[6-char name].org/~[8]/admin` | 0.54 | Legitimate |
| `https://[18-char name].de/[3]/[9]` | 0.60 | Legitimate |
| `http://[15-char name].com/~[8]/[6]` | 0.66 | Legitimate |

## 4. Findings

1. **The main weakness is phishing whose URL looks clean.** 99% of the false negatives contain no credential or financial keywords, 88% use HTTPS, and 77% score below 0.50. The URL text is indistinguishable from an ordinary website, so no URL-only model can separate them.
2. **The brand rule closes part of the gap.** 57 of the 185 put an impersonated brand in the hostname. The live app raises these to Suspicious; the evaluation script does not show this.
3. **Shared hosting.** 4 are on shared hosting platforms. Their verdict rests on the model alone, because the platform's own reputation is deliberately ignored.
4. **Possible improvements** (all need data beyond the URL text): page content (login forms, external form actions, title vs domain), domain age from WHOIS, TLS certificate age, or a live threat-intelligence lookup.

*Generated on 2026-10-05 against the deployed model.*
