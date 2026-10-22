const API_BASE = "http://127.0.0.1:8000/api/extension";
const SCAN_URL = `${API_BASE}/scan`;
const CHECK_BLACKLIST_URL = `${API_BASE}/check-blacklist`;
const REPORT_URL = `${API_BASE}/report`;
const USER_BLOCKS_URL = `${API_BASE}/user-blocks`;

async function authHeaders() {
    const auth = await chrome.storage.session.get("pgAuthToken");
    return auth.pgAuthToken ? { Authorization: `Bearer ${auth.pgAuthToken}` } : {};
}

const HISTORY_LIMIT = 200;

// Local/private hosts (localhost, loopback, LAN, link-local) have no real
// domain reputation to evaluate -- the phishing model reads them as
// suspicious purely because they lack a registrable domain/TLD, which
// would misfire as a false "phishing" warning on the user's own dev
// server or LAN devices. Skip scanning them entirely.
function isLocalOrPrivateHost(hostname) {
    const host = (hostname || "").toLowerCase();
    if (host === "localhost" || host.endsWith(".localhost")) return true;
    if (host === "0.0.0.0" || host === "::1" || host === "[::1]") return true;
    if (/^127\./.test(host)) return true;
    if (/^10\./.test(host)) return true;
    if (/^192\.168\./.test(host)) return true;
    if (/^169\.254\./.test(host)) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return true;
    return false;
}

function isScannable(url) {
    if (typeof url !== "string") return false;
    if (!(url.startsWith("http://") || url.startsWith("https://"))) return false;
    try {
        return !isLocalOrPrivateHost(new URL(url).hostname);
    } catch {
        return false;
    }
}

// Redirect hops of trusted services: a Google search-result click goes
// through google.com/url or google.com/goto (destination often encoded),
// Facebook through l.facebook.com/l.php, Outlook mail links through Safe
// Links. The hop itself is not scanned: its "Trusted" result would describe
// Google, not the site being opened. When the hop forwards with an HTTP
// redirect, the browser reports no new navigation for the real website, so
// that website is scanned when the tab commits it (onCommitted below).
function isRedirectHop(url) {
    try {
        const { hostname, pathname } = new URL(url);
        const host = hostname.toLowerCase();
        const isGoogle = /(^|\.)google\.[a-z.]+$/.test(host);
        return (isGoogle && (pathname === "/url" || pathname === "/goto"))
            || (/(^|\.)(l|lm)\.facebook\.com$/.test(host) && pathname === "/l.php")
            || (/(^|\.)l\.instagram\.com$/.test(host))
            || host.endsWith(".safelinks.protection.outlook.com");
    } catch {
        return false;
    }
}

// ----------------------------------------------------------------
// Session bypass ("Continue Access") — cleared automatically when the
// browser session ends, since chrome.storage.session is in-memory only.
// ----------------------------------------------------------------

async function isBypassed(url) {
    const store = await chrome.storage.session.get("bypassUrls");
    const bypass = store.bypassUrls || {};
    return !!bypass[url];
}

async function removeBypass(url) {
    const store = await chrome.storage.session.get("bypassUrls");
    const bypass = store.bypassUrls || {};
    delete bypass[url];
    await chrome.storage.session.set({ bypassUrls: bypass });
}

async function addBypass(url) {
    const store = await chrome.storage.session.get("bypassUrls");
    const bypass = store.bypassUrls || {};
    bypass[url] = true;
    await chrome.storage.session.set({ bypassUrls: bypass });
}

// ----------------------------------------------------------------
// Local "Block URL" list — immediate per-browser enforcement, separate
// from the server-side admin-approved blacklist.
// ----------------------------------------------------------------

// Matched by HOSTNAME, not the exact URL string. A phishing site is
// blocked as a whole domain, not one specific path/query-string variant of
// it -- matching on the full URL meant revisiting the "same" site (a
// trailing slash, a redirect, a different query string, an http->https
// upgrade) silently skipped the block, which is exactly what was reported
// as "sometimes it shows, sometimes it doesn't". Old entries saved before
// this change have no `hostname` field, so it's derived from `entry.url` on
// the fly as a fallback -- no storage migration needed.
function hostnameOf(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return "";
    }
}

// A notice is shown only on the website it was scanned for. When that
// address redirected straight to another website in the same navigation
// (web3.storage -> storacha.network), the notice is shown there instead,
// naming where the scanned address led.
async function withRedirect(tabId, data) {
    const navKey = `navUrl_${tabId}`;
    const redirectKey = `redirectHost_${tabId}`;
    const store = await chrome.storage.session.get([navKey, redirectKey]);
    if (store[redirectKey] && data.url === store[navKey]) {
        return { ...data, redirectedTo: store[redirectKey] };
    }
    return data;
}

async function isLocallyBlocked(url) {
    const host = hostnameOf(url);
    if (!host) return false;
    const store = await chrome.storage.local.get("userBlockedUrls");
    const list = store.userBlockedUrls || [];
    return list.some((entry) => (entry.hostname || hostnameOf(entry.url)) === host);
}

// Drops the local copy of a domain the user unblocked on the website, so the
// block doesn't come back if they later sign out (a block made while signed
// in is saved both locally and to the account).
async function removeLocalBlock(url) {
    const host = hostnameOf(url);
    const store = await chrome.storage.local.get("userBlockedUrls");
    const list = store.userBlockedUrls || [];
    const kept = list.filter((entry) => (entry.hostname || hostnameOf(entry.url)) !== host);
    if (kept.length !== list.length) {
        await chrome.storage.local.set({ userBlockedUrls: kept });
    }
}

// The local entry's details (when this browser blocked it); null if none.
async function getLocalBlock(url) {
    const host = hostnameOf(url);
    if (!host) return null;
    const store = await chrome.storage.local.get("userBlockedUrls");
    const list = store.userBlockedUrls || [];
    return list.find((entry) => (entry.hostname || hostnameOf(entry.url)) === host) || null;
}

// details: { risk_level, attack_type, reason } from the scan that showed
// the warning page, so the block page can explain the block later.
async function addLocalBlock(url, details = {}) {
    const hostname = hostnameOf(url);
    const store = await chrome.storage.local.get("userBlockedUrls");
    const list = store.userBlockedUrls || [];
    const alreadyBlocked = list.some(
        (entry) => (entry.hostname || hostnameOf(entry.url)) === hostname,
    );
    if (!alreadyBlocked) {
        list.unshift({
            url,
            hostname,
            time: Date.now(),
            risk_level: details.risk_level || null,
            attack_type: details.attack_type || null,
            reason: details.reason || null,
        });
        if (list.length > 500) list.length = 500;
        await chrome.storage.local.set({ userBlockedUrls: list });
    }
}

// ----------------------------------------------------------------
// Detection history (only recorded if the user opted in via options.html)
// ----------------------------------------------------------------

async function recordHistory(entry) {
    const settings = await chrome.storage.local.get("historyRecordingEnabled");
    if (!settings.historyRecordingEnabled) {
        return;
    }

    const store = await chrome.storage.local.get("detectionHistory");
    const history = store.detectionHistory || [];

    history.unshift({
        ...entry,
        time: Date.now(),
    });

    if (history.length > HISTORY_LIMIT) {
        history.length = HISTORY_LIMIT;
    }

    await chrome.storage.local.set({ detectionHistory: history });
}

// ----------------------------------------------------------------
// Warning page handoff — full result data is passed via chrome.storage.session
// (keyed by a short-lived id) rather than crammed into the URL query string.
// ----------------------------------------------------------------

async function showWarningPage(tabId, mode, payload) {
    const id = `w_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;

    const store = await chrome.storage.session.get("warningData");
    const all = store.warningData || {};
    all[id] = { mode, ...payload };
    await chrome.storage.session.set({ warningData: all });

    const target = chrome.runtime.getURL(
        `warning.html?id=${encodeURIComponent(id)}`
    );

    // A tab waiting on the Checking page for this address goes there instead.
    if (mode !== "checking" && await releaseHold(tabId, payload.url, target)) {
        return;
    }
    chrome.tabs.update(tabId, { url: target });
}

// ----------------------------------------------------------------
// Checking page - a website opens only after its result is in. The tab
// shows warning.html in "checking" mode while the scan runs; the result
// then sends it to the website (allowed once, without a second scan), the
// Phishing warning, the Suspicious page or the block page. The Checking
// page replaces itself, so Back skips it. Every scanned website gets it,
// trusted ones included, so each check is visible.
// ----------------------------------------------------------------

// tabId -> {checkId, url} for tabs waiting on the Checking page.
const heldTabs = new Map();

async function holdTab(tabId, url) {
    const checkId = `c_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
    heldTabs.set(tabId, { checkId, url });
    await showWarningPage(tabId, "checking", { url, checkId });
}

// Sends a held tab to target (the website itself or a PhishGuard page).
// False when the tab is not waiting for this address.
async function releaseHold(tabId, url, target) {
    const held = heldTabs.get(tabId);
    if (!held || held.url !== url) {
        return false;
    }
    heldTabs.delete(tabId);
    if (target === url) {
        await allowOnce(url);
    }
    const store = await chrome.storage.session.get("checkResults");
    const results = store.checkResults || {};
    results[held.checkId] = target;
    await chrome.storage.session.set({ checkResults: results });
    return true;
}

// The next navigation to url opens without a scan (it was just checked).
async function allowOnce(url) {
    const store = await chrome.storage.session.get("allowOnce");
    const allowed = store.allowOnce || {};
    allowed[url] = true;
    await chrome.storage.session.set({ allowOnce: allowed });
}

async function takeAllowOnce(url) {
    const store = await chrome.storage.session.get("allowOnce");
    const allowed = store.allowOnce || {};
    if (!allowed[url]) {
        return false;
    }
    delete allowed[url];
    await chrome.storage.session.set({ allowOnce: allowed });
    return true;
}


// ----------------------------------------------------------------
// Legitimate-scan toast — non-blocking, shown by toast.js (a small content
// script) on the page itself, for BOTH ML-legitimate results and the
// trusted-allowlist bypass (both come back from the same /scan call, just
// with a different model_used/trusted_domain).
//
// Delivered two ways because of a real race: the scan involves 1-2 network
// round-trips, and a fast/cached page (e.g. google.com) can finish loading
// and ask for this before that round-trip completes. So: (1) push it via
// tabs.sendMessage the moment it's ready — best-effort, silently ignored if
// the content script isn't listening yet — and (2) also store it in
// session storage so toast.js's own pull request (sent as soon as it loads,
// document_start) can pick it up if the push arrived too early to matter.
// ----------------------------------------------------------------

async function announceSafeToast(tabId, result) {
    let payload = {
        url: result.url,
        verification: result.trusted_domain
            ? "Trusted Domain Allowlist"
            : result.legit_reason === "page_check"
            ? "AI Model + Live Page Check"
            : result.legit_reason === "established_domain"
            ? "AI Model + Domain Age"
            : ["reputable_site", "http_reputable"].includes(result.legit_reason)
            ? "AI Model + Domain Reputation"
            : "AI Detection Model",
        time: Date.now(),
    };

    const key = `safeToast_${tabId}`;
    await chrome.storage.session.set({ [key]: payload });
    payload = await withRedirect(tabId, payload);

    try {
        await chrome.tabs.sendMessage(tabId, {
            action: "SHOW_SAFE_TOAST",
            data: payload,
        });
    } catch (error) {
        // Content script not injected/listening yet — GET_SAFE_TOAST (pull)
        // will pick this up from session storage instead.
    }
}

// Neutral, non-blocking notice for the new "uncertain" verdict (see
// explanations.is_https_only_verdict on the backend) — deliberately NOT the
// green "safe" toast (would falsely reassure) and NOT the red blocking
// warning page (the model isn't actually confident this is phishing).
// Why a result is Suspicious, in one sentence (notice and Suspicious page).
function uncertainReason(result) {
    const lures = result.lures || [];
    const lureText = lures.length <= 1
        ? (lures[0] || "")
        : `${lures.slice(0, -1).join(", ")} and ${lures[lures.length - 1]}`;
    return result.uncertain_reason === "new_domain" && result.stage2
            ? `This website's domain was registered on ${result.stage2.registered}. New domains are common for phishing - only enter details if you are sure who runs it.`
            : result.uncertain_reason === "established_domain" && result.stage2
            ? `Address pattern resembles phishing, but ${result.stage2.domain} has existed since ${result.stage2.registered.slice(0, 4)}. Check the address carefully.`
            : result.uncertain_reason === "short_link"
            ? `Short link (${result.reputation?.domain}): the address does not show which website it opens. Open it only if you trust who sent it.`
            : lures.length > 0
            ? `${result.reputation?.domain} is a well-established website, but the address contains ${lureText}, which phishing pages on shared or hacked websites use.`
            : result.uncertain_reason === "brand_impersonation" && result.lookalike
            ? `"${result.lookalike}" looks like a misspelling of "${result.brand}" on a domain that is not the brand's own. Open ${result.brand} through its official website.`
            : result.uncertain_reason === "brand_impersonation"
            ? `Uses the brand name "${result.brand}" on a domain that is not the brand's own. Open ${result.brand} through its official website.`
            : result.uncertain_reason === "reputable_domain" && result.reputation?.shared
            ? `Hosted on ${result.reputation?.domain}, a well-established service where anyone can share documents or pages. Check who shared the link.`
            : result.uncertain_reason === "reputable_domain"
            ? `Address pattern resembles phishing, but ${result.reputation?.domain} is a well-established website. Check the domain carefully.`
            : result.uncertain_reason === "borderline"
            ? "Some URL characteristics resemble phishing, but not enough to confirm it."
            : "Flagged mainly because the site does not use HTTPS.";
}

async function announceUncertainToast(tabId, result) {
    let payload = {
        url: result.url,
        reason: uncertainReason(result),
        time: Date.now(),
    };

    const key = `uncertainToast_${tabId}`;
    await chrome.storage.session.set({ [key]: payload });
    payload = await withRedirect(tabId, payload);

    try {
        await chrome.tabs.sendMessage(tabId, {
            action: "SHOW_UNCERTAIN_TOAST",
            data: payload,
        });
    } catch (error) {
        // Content script not injected/listening yet — GET_UNCERTAIN_TOAST
        // (pull) will pick this up from session storage instead.
    }
}

// ----------------------------------------------------------------
// Navigation interception — runs BEFORE the target page loads, so a
// phishing domain that fails DNS/never renders is still scanned and
// blocked (the ML model only needs the URL string, not page content).
// ----------------------------------------------------------------

// Tabs whose navigation started on a redirect hop and has not yet reached
// a website of its own.
const pendingHops = new Set();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) {
        return;
    }

    const url = details.url;

    // PhishGuard's own pages (Checking, warnings) are not navigations to a
    // website.
    if (url.startsWith(chrome.runtime.getURL(""))) {
        return;
    }
    heldTabs.delete(details.tabId);

    // The website a Checking page just released: already scanned, and its
    // notice is waiting in session storage for toast.js.
    if (await takeAllowOnce(url)) {
        await chrome.storage.session.remove(`redirectHost_${details.tabId}`);
        await chrome.storage.session.set({ [`navUrl_${details.tabId}`]: url });
        return;
    }

    // A result waiting for the previous page in this tab (e.g. a Google
    // search page that never picked up its "Trusted" notice) must not be
    // shown on the next website.
    await chrome.storage.session.remove([`safeToast_${details.tabId}`, `uncertainToast_${details.tabId}`,
        `redirectHost_${details.tabId}`]);
    await chrome.storage.session.set({ [`navUrl_${details.tabId}`]: url });

    if (isRedirectHop(url)) {
        pendingHops.add(details.tabId);
        return;
    }
    // A hop that forwards with a script starts a new navigation of its own.
    pendingHops.delete(details.tabId);

    await trackScan(details.tabId, url);
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0 || !pendingHops.has(details.tabId) || isRedirectHop(details.url)) {
        return;
    }
    pendingHops.delete(details.tabId);
    await trackScan(details.tabId, details.url);
});

// The server redirected the navigation to another website.
chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0 || !(details.transitionQualifiers || []).includes("server_redirect")) {
        return;
    }
    await chrome.storage.session.set({ [`redirectHost_${details.tabId}`]: hostnameOf(details.url) });
});

chrome.tabs.onRemoved.addListener((tabId) => {
    pendingHops.delete(tabId);
    tabScans.delete(tabId);
});

// Each tab's latest scan, so a page that then fails to load can say what
// PhishGuard found (see onErrorOccurred below).
const tabScans = new Map();

function trackScan(tabId, url) {
    const promise = scanNavigation(tabId, url).catch(() => null);
    tabScans.set(tabId, { url, promise });
    return promise;
}

async function scanNavigation(tabId, url) {
    if (!isScannable(url)) {
        return;
    }

    // Continue Access opens without waiting.
    const bypassed = await isBypassed(url);
    if (!bypassed) {
        await holdTab(tabId, url);
    }

    // Signed in: the user's "Block URL" list lives on their account and is
    // checked server-side by check-blacklist (so unblocking on the website
    // takes effect). The local list is used when signed out, or as a
    // fallback if the server can't be reached.
    const auth = await authHeaders();
    const signedIn = !!auth.Authorization;

    const blockLocally = async () => {
        const entry = await getLocalBlock(url);
        await recordHistory({
            url,
            prediction: "phishing",
            risk_level: entry?.risk_level || "High",
            confidence: null,
            attack_type: "Blocked by user",
        });
        await showWarningPage(tabId, "blocked", {
            url,
            domain: hostnameOf(url),
            blockedBy: "user",
            platform: "PhishGuard Chrome Extension",
            riskLevel: entry?.risk_level || "High",
            attackType: entry?.attack_type || null,
            reason: entry?.reason || null,
            blockedAt: entry?.time || null,
            signedIn,
        });
    };

    // 1. Admin-approved blacklist, then the user's own block list (the
    // account list server-side, or this browser's list when signed out).
    // The admin block comes first: it applies to every user and cannot be
    // unblocked from the user's account, so that is the page to show.
    try {
        const res = await fetch(
            `${CHECK_BLACKLIST_URL}?url=${encodeURIComponent(url)}`,
            { headers: auth },
        );
        const blacklist = await res.json();

        if (blacklist.blocked) {
            await recordHistory({
                url,
                prediction: "phishing",
                risk_level: blacklist.risk_level || "High",
                confidence: null,
                attack_type: blacklist.by_user ? "Blocked by user" : "Blacklisted domain",
            });
            await showWarningPage(tabId, "blocked", {
                url,
                domain: blacklist.domain,
                blockedBy: blacklist.blocked_by || (blacklist.by_user ? "user" : "admin"),
                platform: blacklist.platform || null,
                reportedVia: blacklist.reported_via || null,
                globalBlock: blacklist.global_block === true,
                riskLevel: blacklist.risk_level || "High",
                attackType: blacklist.attack_type || null,
                reason: blacklist.reason || null,
                // Server times are naive UTC.
                blockedAt: blacklist.blocked_at
                    ? Date.parse(String(blacklist.blocked_at).replace(/Z?$/, "Z"))
                    : null,
                signedIn,
            });
            return;
        }
        // Locally blocked by this user ("Block URL") - signed-out only
        if (!signedIn && await isLocallyBlocked(url)) {
            await blockLocally();
            return;
        }
        // The account (not this browser) is the source of truth while
        // signed in: not blocked there means it was unblocked on the website.
        // user_checked guards against an expired token, where the server
        // answered as signed-out and never looked at the account.
        if (signedIn && blacklist.user_checked === true) {
            await removeLocalBlock(url);
        }
    } catch (error) {
        console.error("PhishGuard blacklist check failed:", error);
        if (await isLocallyBlocked(url)) {
            await blockLocally();
            return;
        }
    }

    // Continue Access releases the warning only. It is checked after the
    // block lists, so a website blocked after continuing stays blocked.
    if (bypassed) {
        return;
    }

    // 2. ML analysis (and trusted-domain bypass, handled server-side)
    try {
        const headers = { "Content-Type": "application/json" };
        const auth = await chrome.storage.session.get("pgAuthToken");
        if (auth.pgAuthToken) {
            headers.Authorization = `Bearer ${auth.pgAuthToken}`;
        }

        const response = await fetch(SCAN_URL, {
            method: "POST",
            headers,
            body: JSON.stringify({ url }),
        });

        const result = await response.json();

        chrome.storage.local.set({ lastScan: result });

        await recordHistory({
            url: result.url,
            prediction: result.prediction,
            risk_level: result.risk_level,
            confidence: result.score ? result.score.confidence : result.confidence,
            risk_score: result.score ? result.score.risk_score : null,
            attack_type: result.attack_type?.category || null,
        });

        if (result.prediction === "phishing") {
            await showWarningPage(tabId, "warning", {
                url,
                result,
            });
        } else if (result.prediction === "uncertain") {
            // Asks first, like a Phishing result, in a milder style.
            await showWarningPage(tabId, "suspicious", {
                url,
                result,
                reason: uncertainReason(result),
            });
        } else {
            await announceSafeToast(tabId, result);
            await releaseHold(tabId, url, url);
        }
        return result;
    } catch (error) {
        console.error("PhishGuard scan failed:", error);
        // Backend unreachable: never leave the website stuck on Checking.
        await releaseHold(tabId, url, url);
    }
}

// ----------------------------------------------------------------
// A website that fails to load (DNS/connection failure) gets a
// PhishGuard-branded page instead of Chrome's bare error page, so it is
// clear the website itself is down, not the extension failing: after
// Continue Access (the block was released but the destination may not
// exist), or after a scan that did not warn (it names the result).
// ----------------------------------------------------------------

const NETWORK_ERROR_MESSAGES = {
    "net::ERR_NAME_NOT_RESOLVED": "The domain name does not exist.",
    "net::ERR_NAME_RESOLUTION_FAILED": "The domain name could not be resolved.",
    "net::ERR_CONNECTION_REFUSED": "The server refused the connection.",
    "net::ERR_CONNECTION_TIMED_OUT": "The connection to the server timed out.",
    "net::ERR_CONNECTION_RESET": "The connection was reset by the server.",
    "net::ERR_CONNECTION_CLOSED": "The connection was closed by the server.",
    "net::ERR_ADDRESS_UNREACHABLE": "The server's address could not be reached.",
    "net::ERR_INTERNET_DISCONNECTED": "There is no internet connection.",
    "net::ERR_EMPTY_RESPONSE": "The server did not send any response.",
    "net::ERR_SSL_PROTOCOL_ERROR": "A secure connection could not be established.",
};

chrome.webNavigation.onErrorOccurred.addListener(async (details) => {
    if (details.frameId !== 0) {
        return;
    }

    const message = NETWORK_ERROR_MESSAGES[details.error];
    if (!message) {
        // Not a connectivity failure we recognize (e.g. net::ERR_ABORTED,
        // which normally just means WE redirected the tab) — leave it alone.
        return;
    }

    // Does not touch the bypass list, so the URL is never re-blocked.
    if (await isBypassed(details.url)) {
        await showWarningPage(details.tabId, "unreachable", {
            url: details.url,
            reason: message,
            continued: true,
        });
        return;
    }

    // A scan of this address that did not warn. A Phishing result already
    // replaced the page with the warning, and a blocked one with the block
    // page (no result is returned for those).
    const scan = tabScans.get(details.tabId);
    if (!scan || scan.url !== details.url) {
        return;
    }
    const result = await scan.promise;
    if (!result || result.prediction === "phishing") {
        return;
    }
    await showWarningPage(details.tabId, "unreachable", {
        url: details.url,
        reason: message,
        continued: false,
        prediction: result.prediction,
        trusted: !!result.trusted_domain,
        riskScore: result.score ? result.score.risk_score : null,
    });
});

// ----------------------------------------------------------------
// Messages from warning.html / popup.js / toast.js
// ----------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    (async () => {
        if (message.action === "GET_WARNING_DATA") {
            const store = await chrome.storage.session.get("warningData");
            const all = store.warningData || {};
            sendResponse(all[message.id] || null);
            return;
        }

        if (message.action === "GET_CHECK_RESULT") {
            const store = await chrome.storage.session.get("checkResults");
            const results = store.checkResults || {};
            const target = results[message.checkId] || null;
            if (target) {
                delete results[message.checkId];
                await chrome.storage.session.set({ checkResults: results });
            }
            sendResponse(target);
            return;
        }

        if (message.action === "SKIP_CHECK") {
            // "Open Without Waiting" on a slow check.
            const tabId = sender.tab?.id;
            if (tabId != null) {
                heldTabs.delete(tabId);
            }
            await allowOnce(message.url);
            sendResponse({ ok: true });
            return;
        }

        if (message.action === "GET_SAFE_TOAST") {
            const tabId = sender.tab?.id;
            if (tabId == null) {
                sendResponse(null);
                return;
            }
            const key = `safeToast_${tabId}`;
            const store = await chrome.storage.session.get(key);
            const data = store[key] || null;
            if (data) {
                await chrome.storage.session.remove(key);
            }
            sendResponse(data && await withRedirect(tabId, data));
            return;
        }

        if (message.action === "GET_UNCERTAIN_TOAST") {
            const tabId = sender.tab?.id;
            if (tabId == null) {
                sendResponse(null);
                return;
            }
            const key = `uncertainToast_${tabId}`;
            const store = await chrome.storage.session.get(key);
            const data = store[key] || null;
            if (data) {
                await chrome.storage.session.remove(key);
            }
            sendResponse(data && await withRedirect(tabId, data));
            return;
        }

        if (message.action === "CONTINUE_ACCESS") {
            await addBypass(message.url);
            const tabId = message.tabId ?? sender.tab?.id;
            if (tabId != null) {
                chrome.tabs.update(tabId, { url: message.url });
            }
            sendResponse({ ok: true });
            return;
        }

        if (message.action === "GO_BACK") {
            const tabId = message.tabId ?? sender.tab?.id;
            if (tabId != null) {
                try {
                    await chrome.tabs.goBack(tabId);
                } catch (error) {
                    // No history to go back to — fall back to a safe default.
                    chrome.tabs.update(tabId, { url: "https://www.google.com" });
                }
            }
            sendResponse({ ok: true });
            return;
        }

        if (message.action === "BLOCK_URL") {
            const blockDetails = {
                risk_level: message.riskLevel || null,
                attack_type: message.attackType || null,
                reason: message.reason || null,
            };
            await addLocalBlock(message.url, blockDetails);
            // An earlier Continue Access no longer applies.
            await removeBypass(message.url);

            // Signed in: also save it to the account so the user can see
            // (and unblock) it on the website's Browser Extension page.
            const auth = await authHeaders();
            if (auth.Authorization) {
                try {
                    await fetch(USER_BLOCKS_URL, {
                        method: "POST",
                        headers: { "Content-Type": "application/json", ...auth },
                        body: JSON.stringify({ url: message.url, ...blockDetails }),
                    });
                } catch (error) {
                    console.error("PhishGuard save-block failed:", error);
                }
            }

            try {
                // Signed in: the report is attributed to the account.
                await fetch(REPORT_URL, {
                    method: "POST",
                    headers: { "Content-Type": "application/json", ...(await authHeaders()) },
                    body: JSON.stringify({
                        url: message.url,
                        attack_type: message.attackType || "Unknown",
                        detection_reason: message.reason || "Blocked by user from the warning page",
                        browser_info: (navigator && navigator.userAgent) || "PhishGuard Extension",
                    }),
                });
            } catch (error) {
                console.error("PhishGuard report-on-block failed:", error);
            }

            sendResponse({ ok: true });
            return;
        }
    })();

    return true; // keep the message channel open for the async sendResponse
});

// ----------------------------------------------------------------
// History-recording consent/settings prompt.
//
// By design this opens every time the extension starts up (browser start,
// or the extension being re-enabled after being toggled off) — not just
// the very first time it's ever installed — so the user always sees it
// confirm PhishGuard is active. It does NOT reset any saved preference;
// historyRecordingEnabled keeps whatever the user last chose, this just
// re-shows the settings page where that choice is visible.
//
// chrome.runtime.onInstalled/onStartup, plus the unconditional call at the
// bottom of this file (covers the service worker simply being (re)loaded,
// which is how "the extension was turned back on" actually surfaces —
// there's no dedicated Chrome event for that), can all fire for the same
// wake-up. Guarding only with an awaited chrome.storage.session check was
// racy: two callers could both read "not opened yet" before either finished
// writing, opening two tabs at once. `promptGuardStarted` closes that
// window synchronously (before any await), so only the first caller in a
// given service-worker lifetime gets past it; the session storage flag
// still prevents a second tab if the worker spins down and back up within
// the same browser session.
// ----------------------------------------------------------------

let promptGuardStarted = false;

async function ensureConsentPrompt() {
    if (promptGuardStarted) {
        return;
    }
    promptGuardStarted = true;

    const session = await chrome.storage.session.get("consentPromptOpened");
    if (session.consentPromptOpened) {
        return;
    }

    await chrome.storage.session.set({ consentPromptOpened: true });
    chrome.tabs.create({
        url: chrome.runtime.getURL("options.html"),
    });
}

chrome.runtime.onInstalled.addListener(() => {
    ensureConsentPrompt();
});

chrome.runtime.onStartup.addListener(() => {
    ensureConsentPrompt();
});

ensureConsentPrompt();
