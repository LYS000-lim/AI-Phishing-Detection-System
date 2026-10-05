# PhishGuard AI: Technical System Summary

*AI Phishing Detection System, Final Year Project. Snapshot of the repository on 2026-10-04 (branch `main`, last commit `cc22bfb`). The evaluation scripts in §6 were re-run on this date against the deployed model.*

---

## 1. Overall Architecture and Folder Structure

PhishGuard AI is a URL-based phishing detection system with three clients that share one backend:

```
 ┌──────────────────────┐      ┌───────────────────────┐
 │ React web app (Vite) │      │ Chrome extension (MV3)│
 │ user + admin portals │      │ real-time page guard  │
 └──────────┬───────────┘      └──────────┬────────────┘
            │ REST/JSON + JWT bearer       │ REST/JSON (JWT optional)
            ▼                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │ FastAPI backend (uvicorn, 127.0.0.1:8000)               │
 │  routes_auth / routes_user / routes_admin /             │
 │  routes_extension                                       │
 │                                                         │
 │  Detection pipeline:                                    │
 │  1. URL validation (schemas.py)                         │
 │  2. Trusted-domain allowlist (allowlist.py) ─► Trusted  │
 │  3. Feature extraction, 22 URL features (features.py)   │
 │  4. Random Forest P(phishing) + tuned thresholds        │
 │  5. Missing-HTTPS counterfactual check                  │
 │  6. Domain-reputation cap (Tranco top 250k)             │
 │  7. HTTP rule (reputable http:// pages)                 │
 │  8. Brand-impersonation rule (brands.py)                │
 │  9. Attack-type analysis (phishing_type.py)             │
 │ 10. XAI: SHAP + LIME + text (explanations.py)           │
 └──────────┬──────────────────────────────────────────────┘
            ▼
   SQLite (backend/phishguard.db, SQLAlchemy ORM)
   Model artefacts (outputs/*.joblib, lime_background.npy)
```

### Folder structure

```
AI Phishing Detection System/
├── backend/
│   ├── app/
│   │   ├── main.py             FastAPI app, CORS, router registration, /api/health, /api/metrics
│   │   ├── database.py         SQLAlchemy engine/session, init_db() + self-healing column migrations
│   │   ├── models.py           ORM tables (7)
│   │   ├── schemas.py          Pydantic request/response models, URL + password validation
│   │   ├── auth.py             bcrypt hashing, JWT (HS256) issue/verify, role dependencies
│   │   ├── features.py         URL canonicalisation + 22-feature extractor (shared by training & inference)
│   │   ├── ml_state.py         Loads model/metrics/thresholds; classify_vec(); SHAP/LIME explainers
│   │   ├── explanations.py     Verdict logic, risk levels, evidence cards, plain-language reasons
│   │   ├── phishing_type.py    Attack category/technique analysis (post-verdict)
│   │   ├── allowlist.py        Curated trusted-domain allowlist (~200 registrable domains)
│   │   ├── reputation.py       Tranco-rank domain reputation + hosting-platform exclusion list
│   │   ├── brands.py           Brand-impersonation rule (75 brands mined from phishing feeds)
│   │   ├── email_utils.py      Gmail SMTP sender for 6-digit password-reset codes
│   │   ├── routes_auth.py      /api/auth/*
│   │   ├── routes_user.py      /api/scan, /api/explain, history, dashboards, reports, profile
│   │   ├── routes_admin.py     /api/admin/*
│   │   └── routes_extension.py /api/extension/*
│   ├── tests/                  Evaluation scripts (see §11)
│   ├── requirements.txt
│   └── .env.example            SMTP / secret / CORS configuration template
├── frontend/                   React 18 + Vite SPA
│   └── src/
│       ├── App.jsx, main.jsx, AuthContext.jsx, api.js, dates.js, index.css
│       └── components/
│           ├── auth/           Login, Register, Logout, ForgotPassword
│           ├── user/           Scanner, UserDashboard, UserHistory, BrowserExtension, BlockedWebsites
│           ├── admin/          AdminDashboard, AdminDetectionLogs, AdminUserManagement,
│           │                   ModelAnalytics, AdminBlacklist, AdminScanner, AdminExtensionMonitoring
│           └── Layout, Profile, Learn, DashboardVisuals, DateRangeFilter, Password* helpers
├── extension/                  Chrome Manifest V3 extension
│   ├── manifest.json, background.js (service worker), toast.js (content script)
│   ├── popup.html/js, options.html/js, history.html/js
│   ├── warning.html/js (phishing interstitial), blocked.html/js, common.js, style.css
├── notebooks/
│   ├── Phase1_Model_Training.ipynb       Legacy Phase-1 Decision Tree (50 PhiUSIIL features, GridSearchCV)
│   ├── Model_Comparison_DT_RF.ipynb      Current training pipeline: DT vs RF, threshold tuning
│   ├── harvest_legit_deeplinks.py        Builds legit_deeplinks_sitemaps.csv from Tranco sites' sitemaps
│   └── harvest_phish_feeds.py            Builds phish_feed_urls.csv from Phishing.Database/phishunt/OpenPhish
├── outputs/                    (gitignored) trained models, lookups, metrics, EDA plots, eval results
├── *.csv                       (gitignored) datasets (see §4)
├── requirements.txt            Full Jupyter/data-science environment freeze (UTF-16 encoded)
└── start-dev.bat               Starts backend (.venv uvicorn) and frontend (npm run dev) in two windows
```

---

## 2. Tech Stack

### Languages
- **Python 3.13.5** for the backend, ML training and evaluation scripts
- **JavaScript (ES modules, JSX)** for the React frontend and the Chrome extension
- **HTML/CSS** for the extension pages and global stylesheet
- **SQL** via the SQLAlchemy ORM; SQLite dialect

### Backend (`backend/requirements.txt`; installed versions in `.venv`)

| Library | Pinned / constraint | Installed | Purpose |
|---|---|---|---|
| FastAPI | ==0.115.6 | 0.115.6 | REST API framework |
| Uvicorn [standard] | ==0.34.0 | 0.34.0 | ASGI server |
| scikit-learn | ==1.8.0 | 1.8.0 | Decision Tree / Random Forest |
| joblib | ==1.4.2 | 1.4.2 | Model serialisation |
| NumPy | >=1.26 | 2.5.2 | Numerics |
| pandas | >=2.2 | 3.0.5 | Data handling (training/eval) |
| SHAP | >=0.48,<0.52 | 0.51.0 | TreeExplainer (XAI) |
| LIME | ==0.2.0.1 | 0.2.0.1 | LimeTabularExplainer (XAI) |
| Pydantic (+email) | >=2.9 | 2.13.5 | Validation (`EmailStr` via email-validator 2.3.0) |
| SQLAlchemy | >=2.0 | 2.0.52 | ORM |
| bcrypt | ==4.2.1 | 4.2.1 | Password hashing |
| python-dotenv | >=1.0 | 1.2.3 | `.env` loading |
| PyJWT | >=2.9 | 2.13.0 | JWT access tokens |
| python-multipart | >=0.0.9 | 0.0.32 | Form parsing |
| pytest | ==8.3.4 | 8.3.4 | (listed; see §11) |
| httpx | >=0.27 | 0.28.1 | HTTP client |
| tldextract | >=5.1 | 5.3.2 | Public Suffix List domain parsing (reputation.py) |
| reportlab | >=4.0 | 5.0.1 | PDF export (admin logs / blacklist) |

Used for training and EDA only: matplotlib 3.11.1, seaborn 0.13.2, Jupyter.

### Frontend (`frontend/package.json`; resolved versions from `package-lock.json`)

| Package | Range | Resolved |
|---|---|---|
| react / react-dom | ^18.3.1 | 18.3.1 |
| react-router-dom | ^6.28.0 | 6.30.4 |
| chart.js | ^4.4.7 | 4.5.1 |
| react-chartjs-2 | ^5.2.0 | 5.3.1 |
| vite (dev) | ^6.0.7 | 6.4.3 |
| @vitejs/plugin-react (dev) | ^4.3.4 | 4.7.0 |

Node.js v24.18.0. The app version is 2.2.0, and routes are lazy-loaded with `React.lazy`.

### Browser extension
Chrome **Manifest V3**, version 1.0.0. Permissions: `tabs`, `activeTab`, `storage`, `webNavigation`; host permissions `<all_urls>` plus the local API. It uses a service worker (`background.js`) and a content script (`toast.js`, runs at `document_start`). No third-party libraries.

### Database
**SQLite** (`backend/phishguard.db`) through SQLAlchemy 2.0. The database can be overridden with `PHISHGUARD_DB_URL`. Tables are created on startup with `create_all()`. `database.py` adds missing columns with lightweight self-healing `ALTER TABLE` migrations; Alembic is not used.

### External data/services
- **Tranco top-1M list**, cached as `outputs/tranco_rank.joblib`, for domain reputation
- **Public Suffix List**: the snapshot bundled with tldextract, used offline
- **Gmail SMTP** (App Password) for password-reset codes
- Training only: **Phishing.Database** (GitHub), **phishunt.io**, **OpenPhish** feeds

---

## 3. System Features

### 3.1 Authentication and accounts (web)
- **Register** (`/register`): full name, email and password. The password needs at least 8 characters with an uppercase letter, a lowercase letter, a digit and a special character. A live checklist (`PasswordRequirements.jsx`) and a confirm-match indicator (`PasswordMatch.jsx`) show progress.
- **Login** (`/login`): returns a JWT (HS256) that expires after **7 days**. The token carries `sub`, `role` and `email`. Login and logout times are recorded (`last_login_at`, `last_logout_at`).
- **Forgot password** (`/forgot-password`): emails a **6-digit code**. The code expires after **10 minutes** and is burned after **5 wrong attempts**. Only a SHA-256 hash of `user_id:code` is stored. Requesting a new code invalidates the old one. The response is the same whether or not the email exists, so it does not reveal registered addresses. Without SMTP configured, the code is written to the server log.
- **Profile** (`/profile`): edit name and email, change password, and view account activity.
- **Role-based routing**: `user` and `admin` roles. `require_admin` protects every `/api/admin/*` endpoint, and guest-only routes redirect signed-in users.

### 3.2 User side (web portal)
| Page | Function |
|---|---|
| **Scanner** (`/scanner`) | Enter a URL and get a verdict card: Legitimate, Suspicious, Phishing or Trusted Website. The card shows the phishing/legitimate probabilities, risk level, model used and the 22 extracted features. **AI Analysis** adds Phishing Attack Analysis (category, techniques, indicators), "Why was this detected?" bullets, **AI Explanation Evidence** cards (feature, detected value, SHAP contribution, LIME weight, "What the AI found", "Why it matters") and Security Analysis. A **Report URL** button sends the URL for admin review. |
| **Dashboard** (`/dashboard`) | Personal security overview: scan totals, phishing vs legitimate counts, security advice, recent detection logs, and charts (threat trend line, result doughnut, important URL characteristics, attack category, detection source). Uses the shared DD/MM/YYYY date-range filter. |
| **History** (`/history`) | Website scan history with filters and date range. |
| **Browser Extension** (`/browser-extension`) | Extension status, install guide, history-recording preference, and extension detection history with per-record Explainable AI detail. |
| **Blocked Websites** (`/blocked-websites`) | Domains the user blocked from the extension's warning page while signed in. This is the **only place to unblock** a site, because the block page itself has no unblock button. |
| **Phishing Awareness / Learn** (`/learn`) | Educational content: what phishing is, why it matters, red flags, how a URL becomes a verdict, and the 22 model features by category. Includes per-topic quizzes; best scores are kept in `localStorage`. |

### 3.3 Admin side
| Page | Function |
|---|---|
| **Admin Dashboard** (`/admin`) | System overview: active users, scans, phishing and legitimate counts, extension detections, blocked-URL count, pending reports, most common attack type, most targeted brand, deployed-model accuracy, top users by scans, and the same chart set as the user dashboard across all users. Admin scans are excluded. |
| **Detection Logs** (`/admin/logs`) | Every detection, with search and filters (result, risk, attack type, source, date range), analytics summary, per-detection Explainable AI view, delete, and **CSV/PDF export** of the filtered set. |
| **User Management** (`/admin/users`) | Create, edit (name, email, role, active flag, password) and delete users. |
| **Model Analytics** (`/admin/analytics`) | DT and RF held-out test metrics (phishing class), a comparison bar chart, the deployed model, and **Global SHAP** and **Global LIME** feature-importance charts. |
| **Blacklist Database** (`/admin/blacklist`) | Review queue for reports from the website and the extension. **Save in Database** approves a report and adds its domain to `blocked_urls`, recording source and attack type. **Do Not Save** rejects it. Also shows blacklist statistics, a "Reported By" column, PDF export, and a view of every user's extension blocks. |
| **Admin Scanner** (`/admin/scanner`) | The same Scanner component, using the admin scan endpoint. |
| **Extension Monitoring** (`/admin/extension-monitoring`) | Extension users, extension detections, threats found, and extension detection records. |

### 3.4 Chrome browser extension
- **Real-time protection** (`webNavigation.onBeforeNavigate`, main frame only). Each navigation goes through these checks in order:
  1. The URL is skipped if it is not http(s), or is localhost or a private, loopback or link-local IP.
  2. The URL is skipped if it is on the session bypass list ("Continue Anyway").
  3. When signed out, the local user block list is checked.
  4. `GET /api/extension/check-blacklist` checks the admin blacklist and, when signed in, the user's account block list. A hit shows the **block page**.
  5. `POST /api/extension/scan` returns a verdict:
     - **phishing**: full-page **warning interstitial**
     - **uncertain**: amber "Suspicious" **toast**
     - **legitimate**: green "Safe" **toast**
- **Warning page** (`warning.html`): shows the verdict, risk, attack category and recommendation, with four buttons: **Go Back to Safety**, **Block This Website**, **Report as Phishing** and **Continue Anyway** (adds a bypass).
- **Block page**: says who blocked the site (user or admin blacklist), the platform, risk level, attack type, reason and date. It has **no unblock or continue button**; unblocking happens on the website.
- **Network-error page**: if a bypassed URL then fails to load (DNS or connection error), a PhishGuard-branded explanation replaces Chrome's error page.
- **Popup**: verdict for the current tab's last scan, with a Report URL button for phishing results.
- **Options page**: sign in with a website account. The JWT is stored in `chrome.storage.session`, and token validity is checked. It also has a history-recording consent toggle, and on sign-in the local block list is synced to the account and the block list is shown. While signed in, extension scans are logged to the `detections` table with `source="extension"`.
- **History page**: the last 200 local detections.

### 3.5 URL reporting and blocking workflow
1. **User report (website)**: `POST /api/report-url` creates a `reported_urls` row with status `pending`.
2. **Extension report**: `POST /api/extension/report` creates an `extension_reports` row with status `pending`. The row records the user if signed in, plus the IP address and browser info.
3. **Admin review**: approving a report adds its hostname to `blocked_urls`, which every extension blocks from then on. Rejecting a website report deletes it; rejecting an extension report marks it `rejected`.
4. **Personal block**: "Block This Website" adds the hostname to `user_blocked_urls` when signed in, otherwise to local storage. The website can unblock it. *(Uncommitted at the time of writing: an admin endpoint and UI to unblock any user's block.)*

---

## 4. Datasets, Preprocessing and Features

### 4.1 Datasets
| File | Rows | Use |
|---|---|---|
| `PhiUSIIL_Phishing_URL_Dataset.csv`: PhiUSIIL Phishing URL Dataset, UCI ML Repository ID 967 | 235,795 (134,850 legitimate, 100,945 phishing in raw labels). 56 columns: URL, Domain, TLD, Title, FILENAME, 50 numeric features, label | Main training and test data |
| `legit_augmentation.csv` | 1,173 | Hand-curated legitimate URLs with paths, query strings and http://. Weight ×10 |
| `legit_deeplinks_sitemaps.csv` | 15,855 URLs from 1,370 domains | Real page URLs harvested from sitemaps of Tranco-ranked sites (`harvest_legit_deeplinks.py`, up to 12 per domain). Weight ×2, split **by domain** |
| `phish_feed_urls.csv` | 1,548,012 (Phishing.Database 1,546,542; phishunt 882; OpenPhish 588), first seen 2024-12-18 to 2026-09-27 | Recent phishing for training (before Nov 2025), validation (Nov–Dec 2025) and a time-based "future" test (2026) |
| `realworld_eval_set.csv` | 527 (227 live legitimate login/account/payment pages; 300 OpenPhish) | Real-world evaluation (§6.3) |
| `tranco_legitimate.csv`, `top-1m.csv`, `additional_legitimate_urls.csv` (594), `additional_opensource_urls.csv` (165) | 50,000 / 1M / 759 | False-positive evaluation (§6.4) and reputation ranks |

**Label convention**: raw PhiUSIIL uses 1 = legitimate and 0 = phishing. The training notebook flips this (`y = 1 − label`), so **0 = Legitimate and 1 = Phishing** everywhere in the deployed system.

### 4.2 Preprocessing (`Model_Comparison_DT_RF.ipynb`)
1. Drop duplicate rows and rows with a missing URL.
2. Concatenate the curated augmentation, sitemap deep links and feed phishing, then **de-duplicate by URL**.
3. **Deep-link variants**: for harvested legitimate URLs, generate an `http://` copy (20% chance) and a benign query-string variant (30% chance, e.g. `page=3`, `lang=en`, `q=news`) within the same split.
4. **Feed sampling**: group feed URLs by registered domain, or by full host on shared hosting platforms. Keep at most 2 URLs per group to limit campaign bias, capped at 60,000 for training and 10,000 for validation. Groups appearing in the future test or the real-world set are removed from training and validation, so no test campaign leaks into training.
5. **Only the raw URL string is used.** Features are **recomputed** from it by `compute_features()`, the same function inference uses, so training and serving stay consistent. PhiUSIIL's HTML/page-content columns are not used.
6. **URL canonicalisation** (`canonicalize_url`):
   - add a scheme if missing
   - strip the leading `www.` (PhiUSIIL records every legitimate URL as `www.`, a labelling artefact)
   - strip the `#fragment` and **tracking parameters** (`utm_*`, `fbclid`, `gclid`, `msclkid`, `_ga`, `ref`, …)
   - strip trailing `/` (31% of PhiUSIIL phishing ends in `/` against 0% of legitimate URLs)
7. **Lookup tables** built from the training split only:
   - `tld_probability_lookup`: P(legitimate | TLD)
   - `char_probability_lookup`: P(char | legitimate URL), from 50,000 canonicalised legitimate URLs with +1 smoothing
8. **Sample weights**: augmentation ×10, harvested ×2, feed ×1 (`FEED_WEIGHT`), PhiUSIIL ×1.

### 4.3 Engineered features: the 22 deployed features (`features.py`)
| # | Feature | Definition |
|---|---|---|
| 1 | URLLength | Length of the canonical URL |
| 2 | DomainLength | Length of the netloc |
| 3 | IsDomainIP | 1 if the host is an IPv4/IPv6 address |
| 4 | TLDLegitimateProb | P(legitimate \| TLD) from the training lookup; 0.5 for unseen TLDs |
| 5 | URLCharProb | Mean P(char \| legitimate) over the URL's characters |
| 6 | TLDLength | Length of the TLD |
| 7 | NoOfSubDomain | max(host labels − 2, 0) |
| 8 | HasObfuscation | 1 if a `%xx`, `@` or `0x…` pattern is present |
| 9 | NoOfObfuscatedChar | Count of those patterns |
| 10 | ObfuscationRatio | NoOfObfuscatedChar / URLLength |
| 11 | NoOfLettersInURL | Letter count |
| 12 | LetterRatioInURL | Letters / length |
| 13 | NoOfDegitsInURL | Digit count |
| 14 | DegitRatioInURL | Digits / length |
| 15 | NoOfEqualsInURL | Count of `=` |
| 16 | NoOfQMarkInURL | Count of `?` |
| 17 | NoOfAmpersandInURL | Count of `&` |
| 18 | NoOfOtherSpecialCharsInURL | Non-alphanumerics other than `= ? & / : .` |
| 19 | SpacialCharRatioInURL | Other specials / length |
| 20 | IsHTTPS | 1 if the scheme is https |
| 21 | **NoOfSuspiciousWords** (new) | Distinct credential/financial words in the URL (login, signin, verify, verification, password, account, auth, authenticate, confirm, bank, payment, invoice, billing, wallet, transaction, money, card, credit, debit), whole-token matched |
| 22 | **HasBrandOutsideDomain** (new) | 1 if a known brand alias (Maybank, PayPal, CIMB, Public Bank, RHB, Bank Islam, Google, Microsoft, Apple, Facebook, Instagram, Amazon) appears but the host is not that brand's official domain |

Features 1–20 re-implement PhiUSIIL URL features. Two PhiUSIIL features were deliberately excluded, `URLSimilarityIndex` and `CharContinuationRate`; the Phase-1 ablation showed URLSimilarityIndex was a near-perfect proxy for the label. The legacy Phase-1 model used all 50 numeric PhiUSIIL features, including HTML features such as LineOfCode, HasTitle, NoOfImage, NoOfJS and HasPasswordField. The deployed system is URL-only, so it never needs to fetch the page.

---

## 5. Machine-Learning Models

### 5.1 Current pipeline (`Model_Comparison_DT_RF.ipynb`, trained 2026-09-24)
| Model | Hyperparameters |
|---|---|
| **DecisionTreeClassifier** | `max_depth=12, min_samples_leaf=5, criterion='gini', random_state=42` (others default) |
| **RandomForestClassifier** *(deployed)* | `n_estimators=200, max_depth=20, min_samples_leaf=2, max_features='sqrt', bootstrap=True, criterion='gini', n_jobs=-1, random_state=42` |

**Selection rule**: the model with the higher **phishing-class F1** on the held-out test set becomes `deployment_model.joblib`. **Random Forest won.**

### 5.2 Train / validation / test split
- PhiUSIIL plus curated augmentation: **stratified 80/20** train+val/test, then 15% of train+val held out as validation, giving **68 / 12 / 20**.
- Harvested deep links: split **by domain 70 / 15 / 15**, so validation and test pages come from websites never seen in training.
- Feed phishing: **time-based**. First seen before Nov 2025 goes to train, Nov–Dec 2025 to validation, and 2026 to the "future" test, which is never trained on.
- Final sizes: **n_train = 237,212**, headline **n_test = 47,257** (PhiUSIIL + augmentation test rows; 27,205 legitimate and 20,052 phishing).
- `random_state=42` throughout.

### 5.3 Cross-validation
- **Current pipeline**: no k-fold CV. Hyperparameters are fixed, and a dedicated **validation split** tunes the decision thresholds (§8). The test set is used only for final reporting.
- **Legacy Phase 1** (`Phase1_Model_Training.ipynb`): Decision Tree tuned with **GridSearchCV, 3-fold CV, scoring = F1** over `max_depth ∈ {5, 10, 15, 20, None}`, `min_samples_split ∈ {2, 10, 50}`, `min_samples_leaf ∈ {1, 5, 20}` and `criterion ∈ {gini, entropy}`. It also ran an ablation without `URLSimilarityIndex` and produced EDA output: class distribution, histograms, correlation heatmap, top-20 importances and a depth-3 tree plot (in `outputs/`). This model is superseded and not deployed.

### 5.4 Saved artefacts (`outputs/`)
- `deployment_model.joblib` / `rf_model.joblib` (RF, ~129 MB) and `dt_model.joblib`
- `deployment_features.joblib` (22 feature names) and `deployment_metrics.joblib` (metrics + thresholds)
- `tld_probability_lookup.joblib`, `char_probability_lookup.joblib`, `tranco_rank.joblib`
- `lime_background.npy`: 1,000 training rows used as background for LIME and global SHAP
- `evaluation_metrics.txt`: JSON copy of the metrics

---

## 6. Evaluation Results

### 6.1 Held-out test set (n = 47,257; 0.5 cut-off; positive class = Phishing)
| Metric | Decision Tree | **Random Forest (deployed)** |
|---|---|---|
| Accuracy | 0.9695 | **0.9797** |
| Precision | 0.9847 | **0.9876** |
| Recall | 0.9428 | **0.9644** |
| F1-score | 0.9633 | **0.9759** |
| Deep-link FP rate (unseen real legitimate pages) | 0.1186 | 0.1357 |
| Future-feed recall (2026 phishing, unseen) | 0.8395 | **0.8921** |

**Confusion matrices** (rows = actual, columns = predicted; order [Legitimate, Phishing]):

```
Decision Tree                      Random Forest
            Pred L   Pred P                    Pred L   Pred P
Actual L    26,912      293        Actual L    26,962      243
Actual P     1,147   18,905        Actual P       714   19,338
```

### 6.2 Random Forest with tuned thresholds (as deployed)
| Measure | Value |
|---|---|
| Phishing threshold | **0.89** |
| Suspicious ("uncertain") threshold | **0.73** |
| Test recall at 0.89 (hard Phishing verdict) | 0.9069 |
| Test phishing flagged at ≥ 0.73 (Phishing or Suspicious) | 0.9408 |
| Test FPR at 0.89 | **0.0014** |
| Deep-link FPR at 0.89 / flagged at ≥ 0.73 | 0.0195 / 0.0570 |
| 2026 future-feed recall at 0.89 / flagged at ≥ 0.73 | 0.7797 / 0.8422 |

Derived from these rates at the 0.89 threshold (approximate): TP ≈ 18,185, FN ≈ 1,867, FP ≈ 39, TN ≈ 27,166. That gives **precision ≈ 0.998, recall ≈ 0.907, F1 ≈ 0.950, accuracy ≈ 0.960**.

### 6.3 Real-world evaluation of the full pipeline (`realworld_eval.py`, re-run 2026-10-04)
The set has 227 live legitimate login, account and payment pages (fetched 2026-09-23) and 1,178 phishing URLs in 1,097 campaigns: 300 from OpenPhish plus 878 from phishunt 2026.

| Stage | Legit shown PHISHING | Legit shown Suspicious | Phish shown PHISHING | Phish any warning | Phish PHISHING per campaign |
|---|---|---|---|---|---|
| Model + thresholds only | 12.3% | 18.1% | 74.2% | 84.3% | 74.4% |
| + allowlist | 4.4% | 5.7% | 74.2% | 84.3% | 74.4% |
| + reputation, top 50k | 0.9% | 9.3% | 74.1% | 84.3% | 74.4% |
| + reputation, top 100k | 0.4% | 9.7% | 74.0% | 84.3% | 74.3% |
| **+ reputation, top 250k (deployed)** | **0.0%** | **10.1%** | **73.5%** | **84.3%** | **73.8%** |
| + reputation, top 1M | 0.0% | 10.1% | 72.8% | 84.3% | 73.4% |

**Deployed system by category.** Legitimate pages: 204 shown legitimate, 23 suspicious, 0 phishing. OpenPhish: 201 phishing, 55 suspicious, 44 legitimate. phishunt 2026: 665 phishing, 72 suspicious, 141 legitimate.

Only 1.38% of a 20k PhiUSIIL phishing sample sits on a top-250k domain, so the reputation cap rarely hides real phishing.

### 6.4 Large-scale false-positive check (`batch_eval.py`, 55,758 legitimate URLs, re-run 2026-10-04)
| Source | n | FP @ 0.5 (raw) | Shown PHISHING (0.89) | Phishing or Suspicious (≥ 0.73) |
|---|---|---|---|---|
| Real deep links | 758 | 29.2% | 1.2% | 9.0% |
| Top-1M domains (top 5k) | 5,000 | 2.5% | 0.5% | 1.3% |
| Tranco legitimate | 50,000 | 7.3% | 2.5% | 4.8% |
| **Overall raw FP @ 0.5** | 55,758 | **7.13%** | | |

Most remaining Tranco false positives are numeric or random-looking `.xyz`/`.click` domains (e.g. `889993527.xyz`), which are structurally indistinguishable from phishing.

### 6.5 Categorised manual test suite (`fp_category_tests.py`, 39 URLs, re-run 2026-10-04)
**Raw model at 0.5**: accuracy **0.846**.

**Live app**: accuracy **0.974**.
- Legitimate shown Phishing: 0 of 30. Legitimate shown Suspicious: 1 of 30 (`https://web3.storage`, p = 0.871).
- Phishing shown Phishing: 9 of 9.

Live accuracy was 1.00 in every category except digit_tld_legit (0.667). Categories: bare_root, www_root, subdomain, deep_path, query_string, hyphen_domain, unusual_tld, digit_tld, http legit; ip, typosquat_hyphen, brand_in_path, obfuscated phishing.

### 6.6 Explanation-quality evaluation (`explanation_eval.py`, re-run 2026-10-04)
Rule-based checklist scores, as the mean percentage over applicable URLs:
- Attack Analysis correctness **100%** (9 phishing URLs)
- "Why detected" quality **100%**
- Evidence-card quality **100%**
- SHAP/LIME presentation **100%**

The per-URL report is in `outputs/explanation_eval_report.md`.

---

## 7. Explainable AI (XAI)

| Method | How it is computed | Where it is displayed |
|---|---|---|
| **SHAP (local)** | `shap.TreeExplainer(RandomForest)` (exact Tree SHAP). `shap_values(vec)` gives the class-1 (phishing) contribution for each of the 22 features, and the top 10 by \|value\| are returned. Positive values push towards Phishing. | Scanner, Detection Logs and Extension history XAI views: SHAP contribution on each evidence card, plus the raw top-features list in the API response |
| **LIME (local)** | `LimeTabularExplainer(lime_background.npy [1,000 training rows], mode='classification', class_names=[Legitimate, Phishing], random_state=42)`. `explain_instance(vec, model.predict_proba, num_features=10, labels=[1])` returns rules such as `IsHTTPS <= 0.00` with weights. | Evidence cards show the LIME weight matched to the same feature; raw rules are in the API response |
| **Global SHAP** | Mean \|SHAP\| for each feature over 500 random rows of the LIME background, cached after the first call | Admin → Model Analytics: horizontal bar chart (top 15) |
| **Global LIME** | Mean \|LIME weight\| for each feature, averaged over 40 local explanations of random background rows, cached | Admin → Model Analytics: bar chart (top 15) |
| **Evidence cards** (`build_evidence`) | Combine SHAP and LIME. Keep only features whose SHAP sign supports the verdict, sort by \|SHAP\| and take the top 3. Each card has a title, feature, detected value, SHAP, LIME, a factual "What the AI found" line (compared with training averages) and a "Why it matters" line. | "AI Explanation Evidence" section |
| **Plain-language reasons** (`build_reason_bullets`) | For phishing: paraphrased attack techniques followed by a synthesised sentence on the strongest ML signals. For legitimate: one narrative sentence. Suspicious verdicts get dedicated text for each reason (borderline, missing HTTPS only, reputable domain, brand impersonation). | "Why was this detected?" / "Why is this URL marked suspicious?" / "Why was this classified as legitimate?" |
| **Counterfactual (missing HTTPS)** | Re-score the same vector with `IsHTTPS = 1`. If the result falls below the threshold, missing HTTPS alone is driving the verdict. | Drives the Suspicious "https_only" state and its explanation |
| **Attack-type analysis** (`phishing_type.py`) | Rule-based labelling after a phishing verdict; it never changes the verdict. Categories: Financial Scam, Credential Theft, Fake Giveaway / Scam, Tech Support / Malware Scam, Domain Spoofing / Brand Impersonation. Techniques (up to 3): Brand Impersonation, Typosquatting (look-alike substitution and SequenceMatcher), Credential Harvesting, Fake Security Alert, Malware Delivery, URL Obfuscation, IP Address Hosting, Subdomain Manipulation (≥ 3 subdomains), Suspicious Top-Level Domain (TLD prob < 0.3), Randomized / Numeric Domain (digit ratio > 0.15), Suspicious URL Pattern. | "Phishing Attack Analysis" section; category stored in `detections.attack_type` |

Trusted-allowlist results skip the ML model entirely, so no SHAP or LIME is computed for them. They show "Trusted Domain Verification" instead.

---

## 8. Classification Labels, Risk Levels and Thresholds

### 8.1 Verdict flow (`ml_state.classify_vec` → `explanations.classify`)
Let p = Random Forest P(phishing).

| Step | Condition | Result |
|---|---|---|
| 0 | Registrable domain is on the trusted allowlist | **Trusted Website** (legitimate, p = 0, model `TrustedAllowlist`) |
| 1 | p ≥ **0.89** | **Phishing**, unless `IsHTTPS = 0` and the HTTPS counterfactual scores < 0.73, in which case **Suspicious** (`https_only`) |
| 2 | 0.73 ≤ p < 0.89 | **Suspicious** (`borderline`) |
| 3 | p < 0.73 | **Legitimate** |
| 4 | Reputation cap: Phishing on a domain in the Tranco **top 250,000** that is not a hosting platform | Downgraded to **Suspicious** (`reputable_domain`) |
| 5 | HTTP rule: Suspicious, `http://`, Tranco **top 100,000**, and the HTTPS counterfactual scores below 0.73 (below 0.5 if the URL has a path or query) | Upgraded to **Legitimate** (`http_reputable`) |
| 6 | Brand rule: one of 75 feed-mined brands in the hostname of a domain that is not reputable | Legitimate becomes **Suspicious** (`brand_impersonation`); Suspicious becomes **Phishing** (`escalated_by`) |

Internal labels are `legitimate`, `uncertain` (shown as **Suspicious**) and `phishing`. The DB field `label` always stores the raw 0.5 model decision (0 = Legitimate, 1 = Phishing) for unbiased statistics. Only `prediction` and `risk_level` reflect the post-model layers.

### 8.2 Risk levels
| Verdict | Risk |
|---|---|
| Legitimate / Trusted | **Low** |
| Suspicious (any reason) | **Medium** |
| Phishing | `risk_level(p)`: p < 0.50 Low, 0.50–0.80 Medium, ≥ 0.80 **High**. Phishing requires p ≥ 0.89, so in practice it is High, except brand-escalated cases (p ≥ 0.73), which can be Medium. |

### 8.3 How the thresholds were tuned (validation split only)
- **Phishing threshold**: the smallest t in [0.50, 0.95] with FPR ≤ 1% on PhiUSIIL validation legitimate rows **and** ≤ 2% on harvested deep-link validation pages. Result: **0.89**.
- **Suspicious threshold**: the smallest t ≥ 0.50 that flags ≤ 7% of deep-link validation pages. Result: **0.73**.
- If the metrics file has no thresholds, both fall back to 0.5.

---

## 9. Database Tables and Fields (SQLite, `models.py`)

| Table | Fields |
|---|---|
| **users** | id PK, full_name (120), email (120, unique, indexed), password_hash (bcrypt), role (`user`\|`admin`), is_active, created_at, last_login_at, last_logout_at |
| **detections** | id PK, user_id FK→users (CASCADE), url, prediction (`legitimate`\|`uncertain`\|`phishing`), label (0/1 raw), confidence, phishing_probability, risk_level (Low/Medium/High), model_used (`RandomForest`\|`TrustedAllowlist`), attack_type, ip_address, source (`website`\|`extension`), created_at (indexed) |
| **reported_urls** | id PK, user_id FK→users (CASCADE), url, attack_type, detection_reason, status (`pending`\|`approved`), created_at, reviewed_at |
| **extension_reports** | id PK, url, attack_type, user_id FK→users (SET NULL, nullable = anonymous), detection_reason, ip_address, browser_info, status (`pending`\|`approved`\|`rejected`), created_at, reviewed_at |
| **blocked_urls** (admin blacklist) | id PK, url, domain (unique, indexed), risk_level (default High), reason, source (`Chrome Extension`\|`PhishGuard Website`), attack_type, created_at |
| **user_blocked_urls** | id PK, user_id FK→users (CASCADE), url, hostname (indexed), attack_type, risk_level, reason, created_at; UNIQUE(user_id, hostname) |
| **password_reset_tokens** | id PK, user_id FK→users (CASCADE), token_hash (SHA-256, unique), expires_at, used_at, attempts, created_at |

---

## 10. API Endpoints (FastAPI, base `http://127.0.0.1:8000`)

Auth levels: **P** = public, **U** = signed-in user (JWT), **A** = admin, **O** = optional JWT.

### General
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health` | P | Status, model loaded, deployed model |
| GET | `/api/metrics` | P | DT/RF headline metrics |

### Auth (`/api/auth`)
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/register` | P | Create account |
| POST | `/login` | P | Returns JWT + user |
| GET | `/me` | U | Current user |
| POST | `/logout` | U | Records logout time |
| POST | `/forgot-password` | P | Email a 6-digit reset code |
| POST | `/reset-password` | P | Verify code and set a new password |

### User
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/scan` | U | Scan one URL and log it |
| POST | `/api/scan/batch` | U | Scan a list of URLs |
| POST | `/api/explain` | U | Full XAI (SHAP, LIME, evidence, reasons, attack analysis) |
| GET | `/api/detections` | U | Own history (filters, date range) |
| GET | `/api/detections/history-summary` | U | History summary |
| GET | `/api/detections/dashboard-visuals` | U | Chart data |
| GET | `/api/detections/summary` | U | Personal dashboard stats |
| GET | `/api/detections/{id}` | U | One detection |
| POST | `/api/report-url` | U | Report a URL to the admin |
| GET | `/api/my-reports` | U | Own reports |
| GET | `/api/my-blocked-urls` | U | Own extension blocks |
| DELETE | `/api/my-blocked-urls/{id}` | U | Unblock |
| GET / PATCH | `/api/profile` | U | View / update profile |
| POST | `/api/profile/password` | U | Change password |

### Admin (`/api/admin`)
| Method | Path | Purpose |
|---|---|---|
| GET | `/dashboard` | System-wide stats and charts |
| GET | `/extension-monitoring` | Extension usage stats and records |
| POST | `/scan` | Admin scan |
| GET | `/detections` | All detections (search, filters) |
| DELETE | `/detections/{id}` | Delete a detection |
| GET | `/detections/export?format=csv\|pdf` | Export filtered logs |
| POST / GET | `/users` | Create / list users |
| PATCH / DELETE | `/users/{id}` | Edit / delete a user |
| GET | `/analytics` | DT vs RF metrics, deployed model |
| GET | `/analytics/global-shap?top=15` | Global SHAP importance |
| GET | `/analytics/global-lime?top=15` | Global LIME importance |
| GET | `/reported-urls` | Blacklist database and review queue |
| GET | `/reported-urls/export` | Blacklist PDF |
| POST | `/extension-reports/{id}/approve` · `/reject` | Review extension reports |
| POST | `/user-reports/{id}/approve` · `/reject` | Review website reports |
| GET | `/user-blocked-urls` | Every user's extension blocks |
| DELETE | `/user-blocked-urls/{id}` | Admin unblock *(uncommitted)* |

### Extension (`/api/extension`)
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/scan` | O | Real-time scan. Logged with `source=extension` when signed in |
| GET | `/check-blacklist?url=` | O | Admin blacklist and the user's own block list |
| POST | `/user-blocks` | U | Save a "Block This Website" entry |
| POST | `/user-blocks/sync` | U | Upload local blocks on sign-in |
| POST | `/report` | O | Report phishing from the extension |

FastAPI also auto-generates interactive API docs at `/docs` (Swagger UI) and `/redoc`.

---

## 11. Testing

The project has **no pytest unit tests**: `pytest` is listed, but there are no `test_*` functions. Testing uses scripted evaluation suites and manual functional testing:

| Script | Type | What it tests | Output |
|---|---|---|---|
| `fp_category_tests.py` | Categorised functional test | 39 hand-picked URLs in 13 categories. Compares the raw model at 0.5 with the live pipeline. | `outputs/manual_test_results.csv` |
| `batch_eval.py` | Large-scale FP test | 55,758 held-out legitimate URLs (Tranco, top-1M, deep links) | `outputs/batch_eval_results.csv` |
| `build_realworld_set.py` + `realworld_eval.py` | Real-world / time-based test | Live legitimate login pages vs. current OpenPhish and phishunt phishing. Measures each layer (model, allowlist, reputation) and sweeps the rank cut-off. | console report, `outputs/realworld_eval_results.csv` |
| `explanation_eval.py` + `explanation_scoring.py` | XAI quality test | Runs `/api/explain` logic per URL and scores four deterministic checklists | `outputs/explanation_eval_report.md`, `outputs/explanation_eval_summary.csv` |
| Notebook sanity check | Smoke test | Six known URLs (chatgpt.com, google search, github, wikipedia, `paypa1-secure-login.win/...`, `192.168.0.1/login.php`) | notebook output |

**Example test URLs.**
- Legitimate: `https://numpy.org`, `https://scikit-learn.org`, `https://vercel.app`, `https://web.dev`, `http://example.com`, `http://neverssl.com`.
- Phishing: `http://192.168.0.1/login.php?redirect=%2Fadmin`, `http://45.33.32.156/paypal/login`, `http://paypa1-secure-login.win/verify.php?id=aGVsbG8=&acct=443`, `http://apple-id-verify-account.com/signin`, `http://secure-login-paypal.com/update`, `http://freehost123.net/paypal/login/verify`, `http://bit-secure.xyz/amazon/account/confirm`, `http://phishy-verify.tk/login?id=aGVsbG8=&redirect=%2F%2Fevil.com`, `http://0x4A7D2B1C.xyz/bank/update`.

**Functional and UI testing** was done manually in the browser:
- auth flows, including the Gmail reset code
- scanner verdict states
- dashboards and date filters
- report → admin approve → extension block
- extension warning, toast and block pages
- the extension's signed-in history sync
- CSV/PDF exports

**Input validation**: URLs are rejected if empty, contain spaces, exceed 2,048 characters, lack a dot in the host, or point to localhost or a private IP.

---

## 12. Known Limitations and Unfinished Parts

### Model and detection
1. **URL-only model.** It never inspects page content, so phishing hosted on a **compromised reputable domain** cannot be separated from the real site. Example: `http://math.mak.ac.ug/aux`, HTTPS score 0.28.
2. **Lower recall on recent phishing.** On 2026 feed phishing, 77.97% gets a hard Phishing verdict and 84.2% gets any warning; the real-world set shows 73.5% and 84.3%. About 16% of current phishing is shown as legitimate. Examples: random-looking domains with clean paths such as `wbeuvvfx.com`, and `~user/admin` paths on unranked hosts.
3. **Real login pages are often Suspicious.** 10.1% of live legitimate login and banking pages (Microsoft, Proton, Zoho, Booking.com, Malaysian banks) show Suspicious, because their URLs resemble credential-phishing URLs. The reputation cap prevents a hard Phishing accusation but not the warning.
4. **Dataset artefacts.** PhiUSIIL's legitimate class is almost entirely `https://www.` homepages. This is mitigated by canonicalisation, augmentation, deep links and the HTTP rule, but the raw model still over-weights `IsHTTPS`: 29% raw FP at 0.5 on real deep links.
5. **Label noise.** 162 PhiUSIIL "phishing" rows are real service homepages (ipify.org, coinbase.com, w3.org).
6. **Numeric and random domains on cheap TLDs** (`*.xyz`, `*.click`) are flagged even when legitimate.
7. **Allowlist is a hard string-match bypass.** No certificate or content check, so a compromised allowlisted domain is trusted outright. Allowlist trust is never extended to user-content hosts (`sites.google.com`, etc.).
8. **Static reputation and brand lists.** The Tranco snapshot, hosting-platform list and brand lists must be refreshed manually. The `HasBrandOutsideDomain` feature knows only 12 brands; extending it needs a retrain.
9. **No k-fold cross-validation** in the deployed pipeline; there is a single stratified, grouped and time-based split. Some thresholds (e.g. the HTTP-rule 0.5) were chosen on the same simulation they are reported on, so those figures are slightly optimistic.
10. **Global LIME** averages only 40 instances (for speed), so it is an approximation. It is inherently less stable than SHAP.

### Engineering
11. The root `requirements.txt` is a UTF-16 Jupyter environment freeze, not the backend dependency list. Use `backend/requirements.txt` for the backend.
12. `README.md` is empty.
13. **No automated unit or API tests**; pytest is listed but unused. sklearn warns "X does not have valid feature names" because inference uses NumPy arrays. This is harmless.
14. **Development-grade deployment**:
    - SQLite with hand-written `ALTER TABLE` migrations (no Alembic)
    - default JWT secret unless `PHISHGUARD_SECRET` is set
    - CORS and the extension API URL hard-coded to `localhost`/`127.0.0.1`
    - no HTTPS, no rate limiting on login or scan endpoints
15. The extension is **not published** to the Chrome Web Store; it is loaded unpacked. Its version is 1.0.0 and its description still says "Random Forest model".
16. The blacklist PDF export writes a fixed filename (`PhishGuard_Blacklist_Report.pdf`) to the server's working directory, which could clash under concurrent use.
17. The backend caches the model in memory, so it must be restarted after retraining. Retraining needs the large gitignored CSVs (the 152 MB feed file).
18. **Uncommitted work in progress**: admin unblock of any user's extension block (`DELETE /api/admin/user-blocked-urls/{id}` plus `BlockedWebsites.jsx`).
