const API_BASE = "http://localhost:8000/api/extension";
const SCAN_URL = `${API_BASE}/scan`;
const CHECK_BLACKLIST_URL = `${API_BASE}/check-blacklist`;
const REPORT_URL = `${API_BASE}/report`;

const HISTORY_LIMIT = 200;

function isScannable(url) {
    return (
        typeof url === "string" &&
        (url.startsWith("http://") || url.startsWith("https://"))
    );
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

async function isLocallyBlocked(url) {
    const store = await chrome.storage.local.get("userBlockedUrls");
    const list = store.userBlockedUrls || [];
    return list.some((entry) => entry.url === url);
}

async function addLocalBlock(url) {
    const store = await chrome.storage.local.get("userBlockedUrls");
    const list = store.userBlockedUrls || [];
    if (!list.some((entry) => entry.url === url)) {
        list.unshift({ url, time: Date.now() });
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

    chrome.tabs.update(tabId, { url: target });
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
    const payload = {
        url: result.url,
        verification: result.trusted_domain
            ? "Trusted Domain Allowlist"
            : "AI Detection Model",
        time: Date.now(),
    };

    const key = `safeToast_${tabId}`;
    await chrome.storage.session.set({ [key]: payload });

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

// ----------------------------------------------------------------
// Navigation interception — runs BEFORE the target page loads, so a
// phishing domain that fails DNS/never renders is still scanned and
// blocked (the ML model only needs the URL string, not page content).
// ----------------------------------------------------------------

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) {
        return;
    }

    const url = details.url;

    if (!isScannable(url)) {
        return;
    }

    if (await isBypassed(url)) {
        return;
    }

    // 1. Locally blocked by this user ("Block URL")
    if (await isLocallyBlocked(url)) {
        await recordHistory({
            url,
            prediction: "phishing",
            risk_level: "High",
            confidence: null,
            attack_type: "Blocked by user",
        });
        await showWarningPage(details.tabId, "blocked", {
            url,
            domain: url,
            reason: "You previously chose to block this website.",
        });
        return;
    }

    // 2. Admin-approved blacklist
    try {
        const res = await fetch(
            `${CHECK_BLACKLIST_URL}?url=${encodeURIComponent(url)}`
        );
        const blacklist = await res.json();

        if (blacklist.blocked) {
            await recordHistory({
                url,
                prediction: "phishing",
                risk_level: blacklist.risk_level || "High",
                confidence: null,
                attack_type: "Blacklisted domain",
            });
            await showWarningPage(details.tabId, "blocked", {
                url,
                domain: blacklist.domain,
                reason:
                    blacklist.reason ||
                    "This website was previously reported and confirmed as phishing.",
            });
            return;
        }
    } catch (error) {
        console.error("PhishGuard blacklist check failed:", error);
    }

    // 3. ML analysis (and trusted-domain bypass, handled server-side)
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
            confidence: result.confidence,
            attack_type: result.attack_type?.category || null,
        });

        if (result.prediction === "phishing") {
            await showWarningPage(details.tabId, "warning", {
                url,
                result,
            });
        } else {
            await announceSafeToast(details.tabId, result);
        }
    } catch (error) {
        console.error("PhishGuard scan failed:", error);
    }
});

// ----------------------------------------------------------------
// Continue Access can only release the block — it can't guarantee the
// destination actually exists. If the URL the user just bypassed then
// fails to load (DNS/connection failure), show a PhishGuard-branded
// explanation instead of Chrome's bare error page, so it's clear this is
// a real-world connectivity issue and not the extension failing/re-blocking.
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

    // Only ever shown for a URL the user just released via Continue Access.
    // Does not touch the bypass list, so the URL is never re-blocked.
    if (!(await isBypassed(details.url))) {
        return;
    }

    await showWarningPage(details.tabId, "unreachable", {
        url: details.url,
        reason: message,
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
            sendResponse(data);
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
            await addLocalBlock(message.url);

            try {
                await fetch(REPORT_URL, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        url: message.url,
                        attack_type: message.attackType || "Unknown",
                        detection_reason: "Blocked by user from the warning page",
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
// History-recording consent prompt.
//
// chrome.runtime.onInstalled only reliably fires with reason "install" on
// a genuinely first-ever install; reloading an unpacked extension during
// development fires "update" (or sometimes nothing consistent at all), so
// gating on reason === "install" alone silently skipped the prompt while
// iterating. Instead: whenever the service worker starts up, if consent
// hasn't been recorded yet, open the prompt — guarded by a session flag so
// a MV3 service worker that spins up/down repeatedly doesn't spawn a new
// tab every time it wakes.
// ----------------------------------------------------------------

async function ensureConsentPrompt() {
    const local = await chrome.storage.local.get("historyConsentGiven");
    if (local.historyConsentGiven) {
        return;
    }

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
