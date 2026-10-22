function getQueryParam(name) {
    return new URLSearchParams(window.location.search).get(name);
}

function getCurrentTabId() {
    return new Promise((resolve) => {
        chrome.tabs.getCurrent((tab) => resolve(tab ? tab.id : null));
    });
}

async function init() {
    const card = document.getElementById("pg-card");
    const id = getQueryParam("id");

    if (!id) {
        card.innerHTML = "<p>No warning data found.</p>";
        return;
    }

    let data = null;
    try {
        data = await chrome.runtime.sendMessage({
            action: "GET_WARNING_DATA",
            id,
        });
    } catch (error) {
        console.error("PhishGuard: could not load warning data", error);
    }

    if (!data) {
        card.innerHTML = "<p>This warning has expired. Please navigate to the site again.</p>";
        return;
    }

    const tabId = await getCurrentTabId();
    render(card, data, tabId);
}

function render(card, data, tabId) {
    if (data.mode === "checking") {
        renderChecking(card, data, tabId);
    } else if (data.mode === "suspicious") {
        renderSuspicious(card, data, tabId);
    } else if (data.mode === "blocked") {
        renderBlocked(card, data);
    } else if (data.mode === "unreachable") {
        renderUnreachable(card, data, tabId);
    } else {
        renderWarning(card, data, tabId);
    }
}

// Shown while the address is scanned; the website opens only once the
// result is in (background.js holdTab). Replaces itself, so Back skips it.
const MIN_CHECKING_MS = 800;

function renderChecking(card, data, tabId) {
    card.classList.add("pg-neutral");

    card.innerHTML = `
        <h1>&#128737; PhishGuard AI</h1>
        <h2>Checking This Website…</h2>
        <div class="pg-spinner"></div>
        <p>PhishGuard AI is checking this address before it opens. This usually
        takes a few seconds; a new or unknown website can take a little longer.</p>
        <div class="pg-info">
            <p><b>Website:</b><br><span class="pg-mono">${pgEscape(data.url)}</span></p>
        </div>
        <p class="pg-small" id="pg-slow" hidden>This check is taking longer than usual.</p>
        <button id="pg-back-safety">&#8592; Go Back</button>
        <button id="pg-skip" hidden>Open Without Waiting</button>
    `;

    const backBtn = document.getElementById("pg-back-safety");
    backBtn.addEventListener("click", async () => {
        backBtn.disabled = true;
        await chrome.runtime.sendMessage({ action: "GO_BACK", tabId });
    });

    const skipBtn = document.getElementById("pg-skip");
    skipBtn.addEventListener("click", async () => {
        skipBtn.disabled = true;
        await chrome.runtime.sendMessage({ action: "SKIP_CHECK", url: data.url });
        location.replace(data.url);
    });

    const started = Date.now();
    const poll = async () => {
        let target = null;
        try {
            target = await chrome.runtime.sendMessage({ action: "GET_CHECK_RESULT", checkId: data.checkId });
        } catch (error) {
            // Service worker restarting: ask again.
        }
        if (target) {
            // Kept on screen briefly even for an instant result (trusted
            // websites), so every check is visible rather than a flash.
            setTimeout(() => location.replace(target), Math.max(0, MIN_CHECKING_MS - (Date.now() - started)));
            return;
        }
        if (Date.now() - started > 20000) {
            document.getElementById("pg-slow").hidden = false;
            skipBtn.hidden = false;
        }
        setTimeout(poll, 250);
    };
    poll();
}

// A Suspicious result: asks first, like the Phishing warning, in a milder
// style (some signs of phishing, not enough to confirm it).
function renderSuspicious(card, data, tabId) {
    card.classList.add("pg-caution");
    const result = data.result || {};
    const risk = result.risk_level || "Medium";

    card.innerHTML = `
        <h1>&#9888;&#65039; PhishGuard AI</h1>
        <h2>Suspicious Website – Check Before You Continue</h2>
        <p>PhishGuard AI paused this page because its address shows some signs
        of phishing, but not enough to confirm it. Check that this is the
        website you meant to open before you continue.</p>

        <div class="pg-info">
            <p><b>Website</b><br><span class="pg-mono">${pgEscape(result.url || data.url)}</span></p>
            <p><b>Risk level</b><br>
                <span class="pg-badge ${pgRiskBadgeClass(risk)}">${pgEscape(risk)}</span>
            </p>
            <p><b>Score</b><br>${pgPct(result.score ? result.score.risk_score : result.phishing_probability)}</p>
            ${data.reason ? `<p><b>Why it was flagged</b><br>${pgEscape(data.reason)}</p>` : ""}
        </div>

        <div class="pg-recommendation"><b>What you should do:</b> Only continue if you
        know this website and opened it on purpose. Do not enter passwords or
        payment details unless you are sure who runs it.</div>

        <button id="pg-leave">&#8592; Go Back to Safety (Recommended)</button>
        <button id="pg-block">Block This Website</button>
        <button id="pg-report">Report as Phishing</button>
        <button id="pg-continue">Continue to Website</button>
        <p class="pg-small">A blocked website can only be unblocked by logging in to
        your PhishGuard AI account (Blocked Websites page).</p>
    `;

    wireButtons(result.url || data.url, null, tabId, {
        riskLevel: risk,
        reason: data.reason || "",
    });
}

// The website could not be reached: after Continue Access (continued), or
// after a scan that did not warn (prediction = that scan's result).
function renderUnreachable(card, data, tabId) {
    card.classList.add("pg-neutral");

    const verdict = data.trusted ? "Trusted website"
        : data.prediction === "uncertain" ? "Suspicious"
        : "Legitimate";
    const badge = data.prediction === "uncertain" ? "risk-medium" : "risk-low";
    const intro = data.continued
        ? `<p>You selected <b>Continue Access</b> for this website.</p>
            <p>
                PhishGuard AI has allowed the navigation, but the destination
                website could not be reached.
            </p>`
        : `<p>PhishGuard AI checked this website, but the website itself could
            not be reached. This is not caused by PhishGuard AI.</p>
            <p><b>PhishGuard result:</b><br>
                <span class="pg-badge ${badge}">${pgEscape(verdict)}</span>
                ${data.trusted || data.riskScore == null ? "" : `<span class="pg-small">Score ${pgPct(data.riskScore)}</span>`}
            </p>`;

    card.innerHTML = `
        <h1>&#128737; PhishGuard AI</h1>
        <h2>${data.continued ? "Website Unavailable After Continue Access" : "Website Unavailable"}</h2>

        <div class="pg-info">
            ${intro}
            <p><b>Website:</b><br>${pgEscape(data.url)}</p>
            <p><b>Possible reasons:</b></p>
            <ul class="pg-reasons">
                <li>The domain does not exist</li>
                <li>The website server is offline</li>
                <li>The website is temporarily unavailable</li>
            </ul>
            ${data.reason ? `<p><b>Detail:</b><br>${pgEscape(data.reason)}</p>` : ""}
        </div>

        <div class="pg-recommendation pg-neutral-note">
            PhishGuard AI did not block this website.
        </div>

        <button id="pg-back-safety">&#8592; Return to Safety</button>
        <button id="pg-retry">Try Again</button>
    `;

    const retryBtn = document.getElementById("pg-retry");
    retryBtn.addEventListener("click", () => {
        retryBtn.disabled = true;
        window.location.href = data.url;
    });

    const backBtn = document.getElementById("pg-back-safety");
    backBtn.addEventListener("click", async () => {
        backBtn.disabled = true;
        await chrome.runtime.sendMessage({ action: "GO_BACK", tabId });
    });
}

// Blocked = already on the user's own block list or the admin blacklist.
// Deliberately no buttons (no Continue Access / Go Back / Report): a block
// can only be lifted from the PhishGuard website account, so the page just
// explains who blocked the site, why, and how to unblock it.
function renderBlocked(card, data) {
    const risk = data.riskLevel || "High";
    const byUser = data.blockedBy === "user";
    // Older backends don't send globalBlock, so fall back to the source label.
    const globalBlock = !byUser && (data.globalBlock || data.reportedVia === "Admin (Manual)");
    const category = data.attackType && data.attackType !== "Unknown" ? data.attackType : null;
    const host = data.domain || data.url;

    const platform = byUser
        ? `You blocked this website using the <b>PhishGuard AI Chrome Extension</b>
           ("Block This Website" on the phishing warning page).`
        : globalBlock
        ? `The <b>PhishGuard AI Administrator</b> blocked this website for
           <b>all users</b> (Global Block).`
        : `The <b>PhishGuard AI Administrator</b> added this website to the
           PhishGuard Admin Blacklist${data.reportedVia
               ? ` after reviewing a report submitted via the <b>${pgEscape(data.reportedVia)}</b>`
               : ""}.`;

    const reasons = (data.reason || "")
        .split("\n")
        .map((r) => r.trim())
        .filter(Boolean)
        // Generic report labels say where the report came from, not why.
        .filter((r) => !/^(Reported from|Blocked by user from) /i.test(r));
    if (!reasons.length) {
        reasons.push(byUser
            ? "PhishGuard AI detected this website as phishing and you chose to block it."
            : globalBlock
            ? "An administrator manually blocked this website for all PhishGuard AI users."
            : "An administrator reviewed a phishing report for this website and confirmed it.");
    }

    const unblock = byUser
        ? `
            <ol class="pg-steps">
                <li>Open the PhishGuard AI website
                    (<a href="${PG_WEBSITE_URL}/blocked-websites" target="_blank" rel="noopener">${PG_WEBSITE_URL}</a>)
                    and log in to your account.</li>
                <li>Go to <b>Blocked Websites</b>.</li>
                <li>Click <b>Unblock</b> next to <span class="pg-mono">${pgEscape(host)}</span>.</li>
            </ol>
            <p class="pg-small">The extension will scan this website normally on your next visit.
            ${data.signedIn ? "" : `This browser's extension is not signed in: sign in under
            <b>Extension Settings &rarr; Website Account</b> so the block is saved to your
            account and can be unblocked there.`}</p>`
        : `
            <p>This block was confirmed by an administrator and applies to every
            PhishGuard AI user, so it cannot be unblocked from your account.</p>
            <p class="pg-small">If you believe this website is safe, contact your
            PhishGuard AI administrator and ask for it to be reviewed.</p>`;

    card.innerHTML = `
        <h1>&#9940; PhishGuard AI</h1>
        <h2>Access to This Website Is Blocked</h2>

        <div class="pg-blocked-banner">
            This website was blocked due to
            <span class="pg-badge ${pgRiskBadgeClass(risk)}">${pgEscape(risk)}</span>
            phishing risk. The page was stopped before it loaded, so nothing on it
            could run or collect your information.
        </div>

        <div class="pg-info">
            <p><b>Website</b><br><span class="pg-mono">${pgEscape(data.url)}</span></p>
            <p><b>Domain blocked</b><br><span class="pg-mono">${pgEscape(host)}</span>
                <br><span class="pg-small">Every page on this domain is blocked, not just this address.</span></p>
            <p><b>Risk level</b><br>
                <span class="pg-badge ${pgRiskBadgeClass(risk)}">${pgEscape(risk)}</span>
                <span class="pg-small">${pgEscape(pgRiskMeaning(risk))}</span></p>
            ${category ? `<p><b>Attack type</b><br>${pgEscape(category)}
                <br><span class="pg-small">${pgEscape(pgAttackDescription(category))}</span></p>` : ""}
            <p><b>Blocked by</b><br>${platform}</p>
            ${data.blockedAt ? `<p><b>Blocked on</b><br>${pgEscape(pgFormatTime(data.blockedAt))}</p>` : ""}
            <p><b>Why it was blocked</b></p>
            <ul class="pg-reasons">
                ${reasons.map((r) => `<li>${pgEscape(r)}</li>`).join("")}
            </ul>
        </div>

        <div class="pg-recommendation">
            <b>What you should do:</b> ${pgEscape(pgRecommendation(category))}
            If you already entered a password on this site, change it now and turn on
            two-factor authentication.
        </div>

        <div class="pg-unblock-box">
            <b>${byUser ? "How to unblock this website" : "Can this be unblocked?"}</b>
            ${unblock}
        </div>

        <p class="pg-small pg-footer-note">You can safely close this tab.</p>
    `;
}

function renderWarning(card, data, tabId) {
    const result = data.result || {};
    const attack = result.attack_type || {};
    const reasons = attack.indicators || [];
    const risk = result.risk_level || "High";

    card.innerHTML = `
        <h1>&#9888;&#65039; PhishGuard AI</h1>
        <h2>Phishing Website Detected</h2>
        <p>PhishGuard AI stopped this page before it loaded because its address
        shows strong signs of phishing. Phishing sites imitate trusted websites
        to steal passwords, bank details or personal information.</p>

        <div class="pg-info">
            <p><b>Website</b><br><span class="pg-mono">${pgEscape(result.url || data.url)}</span></p>
            <p><b>Risk level</b><br>
                <span class="pg-badge ${pgRiskBadgeClass(risk)}">${pgEscape(risk)}</span>
                <span class="pg-small">${pgEscape(pgRiskMeaning(risk))}</span>
            </p>
            ${result.score && result.score.confidence == null ? "" : `<p><b>Confidence</b><br>${pgPct(result.score ? result.score.confidence : result.confidence)}</p>`}
            <p><b>Score</b><br>${pgPct(result.score ? result.score.risk_score : result.phishing_probability)}</p>
            <p><b>Attack type</b><br>${pgEscape(attack.category || "Unknown")}
                ${attack.category ? `<br><span class="pg-small">${pgEscape(pgAttackDescription(attack.category))}</span>` : ""}</p>
            ${reasons.length ? `
                <p><b>Why it was flagged</b></p>
                <ul class="pg-reasons">
                    ${reasons.map((r) => `<li>${pgEscape(r)}</li>`).join("")}
                </ul>
            ` : ""}
        </div>

        <div class="pg-recommendation"><b>What you should do:</b> ${pgEscape(pgRecommendation(attack.category))}</div>

        <button id="pg-leave">&#8592; Go Back to Safety (Recommended)</button>
        <button id="pg-block">Block This Website</button>
        <button id="pg-report">Report as Phishing</button>
        <button id="pg-continue">Continue Anyway (Not Recommended)</button>
        <p class="pg-small">A blocked website can only be unblocked by logging in to
        your PhishGuard AI account (Blocked Websites page).</p>
    `;

    wireButtons(result.url || data.url, attack.category || null, tabId, {
        riskLevel: risk,
        reason: reasons.join("\n"),
    });
}

function wireButtons(url, attackCategory, tabId, details = {}) {
    const continueBtn = document.getElementById("pg-continue");
    if (continueBtn) {
        continueBtn.addEventListener("click", async () => {
            continueBtn.disabled = true;
            await chrome.runtime.sendMessage({
                action: "CONTINUE_ACCESS",
                url,
                tabId,
            });
        });
    }

    const leaveBtn = document.getElementById("pg-leave");
    if (leaveBtn) {
        leaveBtn.addEventListener("click", async () => {
            leaveBtn.disabled = true;
            await chrome.runtime.sendMessage({ action: "GO_BACK", tabId });
        });
    }

    const reportBtn = document.getElementById("pg-report");
    const markReported = () => {
        reportBtn.disabled = true;
        reportBtn.textContent = "Reported ✓";
    };
    if (reportBtn) {
        // Already reported (pending or approved): no second report. A report
        // the admin rejected is deleted, so the button comes back.
        fetch(`http://127.0.0.1:8000/api/extension/report-status?url=${encodeURIComponent(url)}`)
            .then((res) => res.json())
            .then((status) => { if (status.reported) markReported(); })
            .catch(() => { /* backend unreachable: keep the button */ });

        reportBtn.addEventListener("click", async () => {
            reportBtn.disabled = true;
            reportBtn.textContent = "Reporting...";
            try {
                const res = await fetch("http://127.0.0.1:8000/api/extension/report", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", ...(await pgAuthHeaders()) },
                    body: JSON.stringify({
                        url,
                        attack_type: attackCategory || "Unknown",
                        // The model's reasons, so an approved report explains
                        // the block on the admin blacklist block page.
                        detection_reason: details.reason || "Reported from PhishGuard warning page",
                        browser_info: navigator.userAgent,
                    }),
                });
                // 409: someone reported it in the meantime.
                if (!res.ok && res.status !== 409) {
                    throw new Error(`HTTP ${res.status}`);
                }
                markReported();
            } catch (error) {
                reportBtn.textContent = "Report failed";
                reportBtn.disabled = false;
            }
        });
    }

    const blockBtn = document.getElementById("pg-block");
    if (blockBtn) {
        blockBtn.addEventListener("click", async () => {
            blockBtn.disabled = true;
            blockBtn.textContent = "Blocking...";
            await chrome.runtime.sendMessage({
                action: "BLOCK_URL",
                url,
                tabId,
                attackType: attackCategory,
                riskLevel: details.riskLevel,
                reason: details.reason,
            });
            blockBtn.textContent = "Blocked ✓";
            // Reload the address: the extension now intercepts it and shows
            // the block page (who blocked it, why, how to unblock).
            window.location.href = url;
        });
    }
}

init();
