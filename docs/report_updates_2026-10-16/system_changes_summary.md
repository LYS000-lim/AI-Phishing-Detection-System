# PhishGuard AI – System Changes (branch `fix/viva-url-detection`, 16 Oct 2026)

Summary of every change made to the system in this round of work, written as input for updating the FYP report. Report text and figures are not included here.

**Status:** committed and merged into `main` (commit 1f910ba, merge 9665598, 19 Oct 2026). 140 automated tests pass, the frontend builds, and all 99 URLs in the viva check list give the expected result.

---

## 1. Background: the problem being solved

The URL model (Random Forest, 22 URL features, thresholds 0.89 Phishing / 0.73 Suspicious) only reads the address text. It was trained on PhiUSIIL, whose legitimate class is almost entirely bare homepages (e.g. `https://www.wiley.com`). As a result, the model treats any real subdomain or long, site-generated path as a phishing sign:

- **Real links shown as Phishing:**
  - a SharePoint/OneDrive folder link scored 99.6%;
  - `onlinelibrary.wiley.com` scored 0.95 on its host alone;
  - Google Forms edit links, Google Scholar (`.com.my`) searches and login pages of real services were also flagged.
- **Phishing missed:** on the URL alone, about 10% of current live phishing is shown as Legitimate.

Adding domains to the trusted allowlist would only patch known examples, so the earlier allowlist additions were **reverted**. The fixes below are general rules and additional machine-learning and page evidence.

---

## 2. Final detection pipeline (order of steps)

| Step | What happens | New / changed |
|---|---|---|
| 1 | URL clean-up; an address typed without `http(s)://` is checked as `https://` | Changed |
| 2 | Redirect unwrapping: Google search-result links (`google.com/url?q=`), Outlook Safe Links, Facebook `l.php` and similar redirects on trusted services are checked by the address they open | **New** |
| 3 | Trusted-domain allowlist (unchanged list); no longer trusts a redirect to an untrusted site, nor `*.cloudapp.azure.com` / `*.netlify.com` user sites | Changed |
| 4 | Stage 1: Random Forest URL model | Unchanged (faster) |
| 5 | **Stage 2: logistic regression combining the stage-1 score with the domain's age** | **New** |
| 6 | Post-model rules: reputation cap, HTTP rule, **reputable-site rule**, **short-link rule**, brand rule (now with **look-alike spellings** and **Malaysian brands**) | New / changed |
| 7 | **Live page check** (server opens the page) for Suspicious results | **New** |
| 8 | Explanation (SHAP, LIME, plain-language reasons) and attack-type analysis | Changed text |

The allowlist is the only step that skips the ML model. Every other step runs after the model and states its reason in the explanation.

---

## 3. Changes in detail

### 3.1 Input and allowlist fixes
- **Typed addresses as https:** `inti.edu.my` is now checked as `https://inti.edu.my`, as a browser opens it. Before, it was checked as `http://`, so the missing-HTTPS signal dominated.
- **Allowlist holes closed:** phishing on customer sub-sites of trusted companies (`*.cloudapp.azure.com`, `*.netlify.com`) is no longer shown as Trusted Website. Netlify's own pages are still trusted.
- **Open-redirect hole closed:** a trusted-domain link that forwards to another website (e.g. `google.com/url?q=https://evil-site`) is judged by the destination. Before, it was shown as Trusted.

### 3.2 Brand rule extensions
- **Look-alike characters** are shown as **Phishing**:
  - digit/letter swaps: 0→o, 1→l/i, 3→e, 4→a, 5→s, 7→t, rn→m, vv→w (e.g. `g00gle.com`, `paypa1.com`, `micros0ft.com`);
  - punycode homographs (e.g. `xn--pypal-4ve.com`).
- **One-letter misspellings** (e.g. `gooogle.com`, `linkedln.com`, `whatsap.com`) raise the verdict one step, because a few real names are one letter from a brand.
- **False-alarm check:** on the 750,000 Tranco domains ranked 250,001–1,000,000, the look-alike check matched 150 (0.02%), mostly typo domains themselves.
- **Malaysian brands added**, each with its official domains:
  - Banks and payments: Maybank, CIMB, Public Bank, RHB, Hong Leong Bank, AmBank, Bank Islam, BSN, Touch 'n Go.
  - Shopping and delivery: Shopee, Lazada, Pos Laju, DHL, FedEx.
  - Government (official domains under `.gov.my`): LHDN, JPJ, KWSP, PDRM, MySejahtera, PTPTN, PERKESO.
  - Others: Petronas, Celcom.
- The explanation and attack analysis name the imitated brand and the imitating text.

### 3.3 Reputable-site rule (fixes real deep links)
A Suspicious `https://` URL becomes **Legitimate** when all of the following hold:
1. The domain is in the Tranco top 100,000.
2. The domain is not a shared platform whose subdomains belong to other people. That list (`abused_platforms.txt`, 302 domains) is built automatically from the phishing data: domains with phishing on 3 or more different subdomains in PhiUSIIL and feed URLs from before 2026. It is not chosen by hand.
3. The model does not flag the site's own homepage (below the Suspicious threshold).
4. The address has **no lure**. A lure is any of:
   - login/payment wording;
   - another company's brand name;
   - an embedded link to another website;
   - a `user@` prefix;
   - a page inside WordPress system folders (`wp-admin`, `wp-includes`, `wp-content/plugins|themes`, `.well-known`, `cgi-bin`).

**Shared document services** (SharePoint, OneDrive, Google Docs/Drive/Forms, Microsoft Forms, Dropbox, Box, WeTransfer, Read the Docs, raw.githubusercontent.com) keep their parent domain's reputation. They are never on the allowlist, and their result carries the note "anyone can share files here – check who sent the link".

**Measured:**
- Legitimate deep links that were Suspicious: **173 of 174** now Legitimate.
- Known phishing on top-ranked domains now shown Legitimate: 771 of 9,395. 591 of these are Google Docs/SharePoint documents, which look identical to real shared documents from the URL alone. Before the rule was narrowed with conditions 1 and 2, this was 5,005.

### 3.4 Short-link rule
Links on shorteners (bit.ly, tinyurl, forms.gle, 1drv.ms, t.co, cutt.ly, lnkd.in and others) hide their destination, so they are at least **Suspicious**. When the link works, the live page check follows it and the **destination** decides the result.

### 3.5 Live page check (server side)
For a URL that is still Suspicious, the server opens the page once, read-only.

**How it fetches safely**
- **No interaction:** HTML only; scripts are never run, no form is submitted and no cookies are sent.
- **Network guard:** private, loopback, internal and link-local addresses are refused, and only ports 80/443/8080/8443 are allowed. This prevents misuse of the server to reach the internal network.
- **Limits:** 6 seconds for the whole chain, at most 1 MB of HTML and 5 redirects (HTTP, meta refresh and simple JavaScript redirects).
- **Caching:** results are kept for 10 minutes, so the scan and its explanation agree.

**What it looks for**

| Kind | Signal |
|---|---|
| Risk | Password form sends data to another website that is not well established |
| Risk | Password form sends data by e-mail (`mailto:`) |
| Risk | Page code sends form data to a Telegram bot, webhook or form-collection service |
| Risk | Page asks for a password/card details while showing another company's name (title, site name, copyright, logos) |
| Risk | An online form service (Google/Microsoft Forms etc.) asks for a password or OTP |
| Risk | The link redirects on to an address the URL check flags as phishing |
| Safe | The page names only its own website (title/site name/copyright) |
| Safe | Its sign-in form sends the password to the same site (or to the company's other well-established domain) |
| Info | Redirect chain, page unreachable, HTTP error, file instead of page, invalid certificate, sign-in wall |

**How it changes the verdict**
- A **risk** raises Suspicious to **Phishing**.
- On a well-established domain, a page that loads, names only itself and has no risk lowers Suspicious to **Legitimate**.
- A Phishing result is never lowered; for Phishing results the findings are shown in the explanation only.

**Measured on live pages:**
- Real-world legitimate URLs wrongly Suspicious: 21 → 4.
- Legitimate deep links wrongly Suspicious: 73 → 27.
- No legitimate URL turned into Phishing.
- Today's live phishing: 4 more shown as Phishing, none wrongly cleared.
- Time: median about 1–2 s per checked URL.

### 3.6 Stage-2 model: URL score + domain age (machine learning)
- **Idea:** phishing domains are usually bought days or weeks before an attack; genuine websites keep their domains for years. The URL text cannot show this.
- **Domain age lookup:** RDAP (the registries' JSON service, located through IANA's bootstrap file). Endings without RDAP (e.g. `.my`) fall back to WHOIS. Results are cached.
- **Measured separation:** age alone separates phishing from legitimate URLs better than the URL model on the same URLs (AUC 0.905 vs 0.863).

| Domain age when seen | Legitimate | Phishing |
|---|---|---|
| under 1 month | 1 | 179 |
| 10+ years | 1,340 | 53 |

- **Model:** logistic regression with two inputs:
  - the log-odds of the stage-1 score;
  - log(1 + domain age in days).

  Coefficients: +0.588 and −0.959, intercept 6.025. Thresholds: Suspicious from 0.40, Phishing from 0.66. These were tuned so legitimate URLs are warned no more often than by stage 1.
- **Training data:** only URLs stage 1 never trained on:
  - phishing: feed URLs first seen in 2026 plus the OpenPhish/phishunt feeds of 16 Oct 2026;
  - legitimate: the real-world evaluation set, held-out harvested deep links, and homepages of Tranco domains ranked 250,001–1,000,000.
- **Split:** by date for phishing (September → train, 16 Oct → test); by domain (70/30) for legitimate.
- **When it is skipped:** shared hosting (the age would be the platform's), short links, IP addresses, or no age found within 3 seconds. In those cases the URL model decides alone.
- **Safeguard:** on an old domain, a strong lure (another brand, a link elsewhere, `user@`, software folders) keeps the result at Suspicious rather than Legitimate, because a hacked old website keeps its age.

**Test results (unseen data)**

| | URL model alone | Stage 2 |
|---|---|---|
| AUC | 0.823 | **0.939** |
| Phishing warned | 60.4% | **84.7%** |
| Phishing called Phishing | 54.1% | **70.3%** |
| Legitimate warned | 9.7% | **7.4%** |
| Legitimate called Phishing | 3.4% | **2.6%** |

### 3.7 Combined effect on live phishing (764 URLs from the 16 Oct 2026 feeds)

| | Before this round | Full system now |
|---|---|---|
| Shown as Phishing | 604 (79.1%) | **666 (87.2%)** |
| Any warning (Phishing or Suspicious) | 686 (89.8%) | **722 (94.5%)** |
| Missed (shown Legitimate) | 78 | **42** |

**Legitimate URLs wrongly Suspicious**
- Real-world set: 21 → 1.
- Deep-link set: 73 → 18.
- No legitimate URL became Phishing.

These two legitimate sets were partly used to train stage 2, so they are optimistic. Separate URL lists never used in training (365 well-known homepages, 274 deep links, 80 reference links) showed the same direction with no new false alarms.

### 3.8 Explanation (XAI) and interface changes
- **"Why" text:** every new reason has its own wording in place of only "URL length / word count". The reasons covered are:
  - redirect, short link, reputable site and shared document;
  - lure found;
  - page check raised or lowered the verdict;
  - new or established domain;
  - look-alike brand.
- **Scanner page**
  - **New "Domain Age Check (Stage 2 Model)" panel:** registration date, URL pattern score, stage-2 probability and thresholds.
  - **New "Live Page Check" panel:** each finding with ✓ / ⚠ / ℹ.
  - **Redirect line:** "result is for the address it opens".
  - **Score label:** "URL Pattern Score" is shown when a later step changed the verdict.
- **Extension:**
  - toast texts for the new reasons;
  - the popup treats the new reasons as rule-decided;
  - the safe toast names the deciding layer ("AI Model + Domain Age", "AI Model + Live Page Check").
- **Learn page:** pipeline expanded to 10 steps (adds Stage 2, live page check and the new rules).

### 3.9 Result page layout and admin logs
- **"How this result was decided" box** under the verdict. It shows one plain line per step that ran (URL check, domain age, safety rule, page check), each with a label such as "Legitimate", "Raised to Suspicious" or "No change". No percentages are shown in this box.
- **Detail panels moved:** "Domain age details" and "Live page check details" are collapsible rows at the bottom of the result page, closed by default. Model numbers and thresholds appear only inside them.
- **Legitimate explanations:** a Legitimate result decided by a later step (old domain, reputable site, page check) now also ends with the model's own sentence about the signals that pointed to legitimate.
- **Detection Logs:** the "All Users" tab now lists every scan, including admins' Admin Scanner scans, and has an "Admin Scanner" source filter. A new **"My Scans"** tab lists only the signed-in admin's own scans. CSV/PDF export follows the tab. The Admin Dashboard statistics still leave admin test scans out.

### 3.10 Other fixes found during system testing
- **PDF exports:** admin Detection Logs and Blacklist PDFs were unreadable. They are rebuilt as A4 landscape tables with wrapped columns. The Blacklist export no longer leaves a stray PDF file in the project folder.
- **Logout:** opening the Logout page directly showed "Goodbye, there". It now waits for the signed-in user and shows their name.
- **Favicon:** the browser tab now shows a shield icon.
- **Speed:** each prediction now uses one thread (30 ms → 10 ms). Model Analytics first load went from ~2.5 min to ~8 s. A harmless scikit-learn feature-name warning is silenced.

---

## 4. Testing summary
- **Automated tests:** 110 → **140**, all passing.
  - `test_page_check.py` (20 tests): page signals, the network guard against internal addresses, the verdict rules, API scan/explain agreement and short-link following.
  - `test_stage2.py` (9 tests): an age effect on the probability, raising for a new domain, lowering for an old domain, the cases where stage 2 is skipped, unknown age, scan/explain agreement and the strong-lure safeguard.
  - `test_integration.py`: one new test for the My Scans tab and the All Users list.
  - The test setup switches off network-dependent features (`PHISHGUARD_PAGE_CHECK=0`, `PHISHGUARD_STAGE2=0`); the new tests use stubs.
- **Viva URL check list** (`backend/tests/viva_url_checks.py`): **99 / 99** expected results through the live pipeline. Before the fixes, main got 45 of the original 76 URLs right.
  - Groups: typed addresses, famous sites, academic links, Malaysian sites, login pages, cloud documents, lures on shared services, short links, redirects, typosquats, Malaysian scams and phishing patterns.
- **Browser checks:** portal pages verified with no console errors.

---

## 5. Known limitations (to state honestly)
1. **The URL model's bias remains.** The rules and stage 2 correct it, but a real deep link on a small, young website can still be flagged. Retraining the URL model would be the root fix.
2. **Shared documents:** phishing inside a SharePoint file or Google Form with no lure in its address is shown as Legitimate, with a "check who shared it" note.
3. **Live page check limits:**
   - phishing kits can show servers a blank page (cloaking);
   - pages behind sign-in show only the sign-in page;
   - script-only pages expose little HTML;
   - phishing is often taken down within hours;
   - it adds about 1–2 s, at most about 6 s.
4. **Domain age limits:**
   - some endings return no date (e.g. some `.au`), and WHOIS can time out;
   - a hacked old website keeps its age (partly covered by the lure safeguard);
   - 4 live phishing URLs were lost on old domains whose brands are not in the brand list (Dropbox, Vodafone, BBVA).
5. **Internet needed:** the new layers need internet access. Offline, the URL model and rules decide alone.
6. **Brand coverage:** the brand checks know about 100 brands.
7. **Extension display:** the extension shows the verdict but not the full list of server page-check findings (the website scanner does).

---

## 5a. URLs the final system still gets wrong (checked 19 Oct 2026)

| URL | Truth | System shows | Why |
|---|---|---|---|
| `https://www.youtub3.com` | Phishing (look-alike) | Legitimate | Old parked domain; "3" for "e" at the end is not caught as a look-alike of a brand in the list |
| `https://www.yahooo.com` | Phishing (typo) | Legitimate | Old typo domain; the misspelling rule needs brands of 6+ letters |
| `https://roblox.com.pt` | Phishing | Legitimate | Brand on a country ending, URL looks normal, domain not young |
| `http://math.mak.ac.ug/aux` | Phishing (hacked site) | Legitimate | Hacked old university site; nothing in the URL or domain age shows it |
| `http://dropbox.rev.it`, `https://business-dropbox.me`, `https://simulador-credito-auto-bbva.ideeo.mx` | Phishing | Legitimate | Old domains; Dropbox and BBVA are not in the brand list, so the age lowers the result |
| `https://someuser.github.io/portfolio/` | Legitimate | Phishing | GitHub Pages is user hosting with no reputation; the URL model alone decides |
| `https://web3.storage` | Legitimate | Suspicious | Unusual ending; borderline URL score |
| `https://amazon.co.th/` | Legitimate | Suspicious | Low-ranked Amazon country domain, so the brand rule raises it |
| `http://httpforever.com/` | Legitimate | Suspicious | Plain-HTTP site outside the top 100,000 |
| `https://bit.ly/3xYzAbC` (dead short link) | Unknown | Suspicious | A short link that leads nowhere cannot be checked |

These match the limitations in section 5: brand-list coverage, hacked old websites, shared hosting, and URLs whose page cannot be checked.

## 6. Files

**New**
- `backend/app/page_check.py` – safe page fetching, page facts and signals
- `backend/app/pipeline.py` – the full check shared by scan, explanation and extension
- `backend/app/domain_age.py` – RDAP/WHOIS domain age lookup with cache
- `backend/app/stage2.py` – stage-2 model loading, scoring and description
- `backend/app/abused_platforms.txt` – generated list of 302 shared platforms
- `notebooks/build_abused_platforms.py` – builds that list from phishing data
- `notebooks/train_stage2.py` – builds the stage-2 dataset, trains, tunes thresholds, saves the model and metrics
- `backend/tests/test_page_check.py`, `backend/tests/test_stage2.py`, `backend/tests/viva_url_checks.py`

**Changed**
- **Backend:** `allowlist.py`, `brands.py`, `phishing_type.py`, `reputation.py`, `ml_state.py`, `schemas.py`, `routes_user.py`, `routes_extension.py`, `routes_admin.py`, `explanations.py`, `requirements.txt` (adds beautifulsoup4, lxml)
- **Frontend:** `Scanner.jsx`, `Learn.jsx`, `Logout.jsx`, `index.css`, `index.html`
- **Extension:** `background.js`, `popup.js`
- **Tests:** `conftest.py`

**Generated data (not in git):**
- `outputs/stage2_model.joblib`, `outputs/stage2_metrics.json`, `outputs/stage2_set.csv`
- `outputs/domain_age_cache.json`, `outputs/rdap_bootstrap.json`
- `phish_feed_live_2026_10_16.csv`

---

## 7. Still to do
- Update the report (Chapters 3–5: design, implementation, evaluation, testing tables) with these changes.
- Re-run the full evaluation scripts on all evaluation sets for final report numbers.
