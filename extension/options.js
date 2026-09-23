const BLOCKED_LIST_PREVIEW_LIMIT = 10;
const AUTH_LOGIN_URL = "http://127.0.0.1:8000/api/auth/login";
const USER_BLOCKS_SYNC_URL = "http://127.0.0.1:8000/api/extension/user-blocks/sync";
const AUTH_ME_URL = "http://127.0.0.1:8000/api/auth/me";
const MY_BLOCKED_URL = "http://127.0.0.1:8000/api/my-blocked-urls";

// History + blocked-URL sections are only shown while signed in, so every
// report/block made from them is tied to a known account.
function showAccountSections(signedIn) {
    document.getElementById("pg-account-only").style.display = signedIn ? "block" : "none";
    document.getElementById("pg-signin-note").style.display = signedIn ? "none" : "block";
}

// ----------------------------------------------------------------
// Website account sign-in — stores the JWT the same website login
// returns, so background.js can attach it to /api/extension/scan and
// have those detections logged to the signed-in user's account.
//
// Kept in chrome.storage.session (in-memory, cleared when the browser
// session ends) rather than chrome.storage.local, by design: the extension
// must always ask for sign-in and re-request access again on the next
// browser session instead of silently staying signed in indefinitely.
//
// Important: a stored token can go stale (expired, or the account's
// password/email changed elsewhere) without the extension ever finding
// out, since /api/extension/scan treats a bad token as "just scan
// anonymously" rather than an error - by design, so a stale credential
// never breaks the actual phishing protection. That means the ONLY way
// this UI can catch it is by actively re-checking with the server, not
// just trusting that a token is sitting in storage. Without this check,
// the page would keep claiming "Signed in" while every new detection
// silently stopped being recorded, with no obvious way to notice short
// of a full sign-out/sign-in - which fixed it only by coincidence
// (it obtains a fresh token).
// ----------------------------------------------------------------

async function refreshAccountStatus() {
    const store = await chrome.storage.session.get(["pgAuthToken", "pgAuthEmail"]);
    const signedOutEl = document.getElementById("pg-signed-out");
    const signedInEl = document.getElementById("pg-signed-in");

    if (!store.pgAuthToken) {
        signedOutEl.style.display = "block";
        signedInEl.style.display = "none";
        showAccountSections(false);
        return;
    }

    // Optimistically show signed-in with the cached email immediately,
    // then confirm against the server and correct it if the token is dead.
    signedOutEl.style.display = "none";
    signedInEl.style.display = "block";
    document.getElementById("pg-account-email").textContent = store.pgAuthEmail || "";

    try {
        const res = await fetch(AUTH_ME_URL, {
            headers: { Authorization: `Bearer ${store.pgAuthToken}` },
        });
        if (!res.ok) {
            throw new Error("token no longer valid");
        }
        const user = await res.json();
        document.getElementById("pg-account-email").textContent = user.email;
        if (user.email !== store.pgAuthEmail) {
            await chrome.storage.session.set({ pgAuthEmail: user.email });
        }
        showAccountSections(true);
        // Upload any blocks made while signed out, then show the
        // account's list (the same one the website shows).
        await syncLocalBlocks(store.pgAuthToken);
        await renderBlockedList(store.pgAuthToken);
    } catch (error) {
        // Token expired/invalid (or offline - we don't distinguish, since
        // either way the honest state right now is "not confirmed signed
        // in"). Clear it so scans stop pretending to be authenticated and
        // the user sees an accurate sign-in prompt instead of a stale
        // "Signed in" label that no longer means anything.
        await chrome.storage.session.remove(["pgAuthToken", "pgAuthEmail"]);
        signedOutEl.style.display = "block";
        signedInEl.style.display = "none";
        showAccountSections(false);
    }
}

async function signIn() {
    const email = document.getElementById("pg-login-email").value.trim();
    const password = document.getElementById("pg-login-password").value;
    const errorEl = document.getElementById("pg-login-error");
    errorEl.style.display = "none";

    if (!email || !password) {
        errorEl.textContent = "Enter your email and password.";
        errorEl.style.display = "block";
        return;
    }

    try {
        const res = await fetch(AUTH_LOGIN_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.detail || "Sign in failed.");
        }
        await chrome.storage.session.set({
            pgAuthToken: data.access_token,
            pgAuthEmail: data.user?.email || email,
        });
        document.getElementById("pg-login-password").value = "";
        await refreshAccountStatus();
    } catch (error) {
        errorEl.textContent = error.message || "Sign in failed.";
        errorEl.style.display = "block";
    }
}

// Upload URLs blocked while signed out, so the account's block list
// (shown on the website) includes them. Failure is non-fatal.
async function syncLocalBlocks(token) {
    const store = await chrome.storage.local.get("userBlockedUrls");
    const list = store.userBlockedUrls || [];
    if (!list.length) return;
    try {
        await fetch(USER_BLOCKS_SYNC_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
            body: JSON.stringify(list.map((e) => ({ url: e.url, time: e.time }))),
        });
    } catch (error) {
        console.error("PhishGuard block sync failed:", error);
    }
}

async function signOut() {
    await chrome.storage.session.remove(["pgAuthToken", "pgAuthEmail"]);
    await refreshAccountStatus();
}

document.getElementById("pg-sign-in").addEventListener("click", signIn);
document.getElementById("pg-sign-out").addEventListener("click", signOut);

async function refreshStatus() {
    const store = await chrome.storage.local.get("historyRecordingEnabled");
    const enabled = !!store.historyRecordingEnabled;

    const statusEl = document.getElementById("pg-history-status");
    statusEl.textContent = enabled ? "● ON" : "● OFF";
    statusEl.className = enabled ? "pg-value pg-status-on" : "pg-value pg-status-off";

    document.getElementById("pg-enable-history").classList.toggle("selected", enabled);
    document.getElementById("pg-disable-history").classList.toggle("selected", !enabled);
}

async function setHistoryRecording(enabled) {
    await chrome.storage.local.set({
        historyRecordingEnabled: enabled,
        historyConsentGiven: true,
    });
    await refreshStatus();
}

async function renderBlockedList(token) {
    let list = null;
    if (token) {
        try {
            const res = await fetch(MY_BLOCKED_URL, { headers: { Authorization: `Bearer ${token}` } });
            if (res.ok) {
                // created_at is naive UTC from the server.
                list = (await res.json()).map((b) => ({ url: b.url, time: Date.parse(`${b.created_at}Z`) }));
            }
        } catch (error) {
            console.error("PhishGuard: could not load account block list", error);
        }
    }
    if (!list) {
        const store = await chrome.storage.local.get("userBlockedUrls");
        list = (store.userBlockedUrls || []).slice().sort((a, b) => b.time - a.time);
    }
    const container = document.getElementById("pg-blocked-list");
    const viewAllRow = document.getElementById("pg-view-all-row");

    if (!list.length) {
        container.className = "pg-empty";
        container.textContent = "No blocked URLs.";
        viewAllRow.style.display = "none";
        return;
    }

    container.className = "";
    container.innerHTML = list
        .slice(0, BLOCKED_LIST_PREVIEW_LIMIT)
        .map(
            (entry, index) => `
                <div class="pg-history-item">
                    <div class="pg-url">${index + 1}. ${pgEscape(entry.url)}</div>
                    <div class="pg-meta">Time: ${pgFormatTime(entry.time)}</div>
                </div>
            `
        )
        .join("");

    viewAllRow.style.display = list.length > BLOCKED_LIST_PREVIEW_LIMIT ? "flex" : "none";
}

document.getElementById("pg-enable-history").addEventListener("click", () => setHistoryRecording(true));
document.getElementById("pg-disable-history").addEventListener("click", () => setHistoryRecording(false));

refreshStatus();
refreshAccountStatus();
