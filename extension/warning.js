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
    if (data.mode === "blocked") {
        renderBlocked(card, data);
    } else if (data.mode === "unreachable") {
        renderUnreachable(card, data, tabId);
    } else {
        renderWarning(card, data, tabId);
    }
}

function renderUnreachable(card, data, tabId) {
    card.classList.add("pg-neutral");

    card.innerHTML = `
        <h1>&#128737; PhishGuard AI</h1>
        <h2>Website Unavailable After Continue Access</h2>

        <div class="pg-info">
            <p>You selected <b>Continue Access</b> for this website.</p>
            <p>
                PhishGuard AI has allowed the navigation, but the destination
                website could not be reached.
            </p>
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
    `;

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
            <p><b>Model confidence</b><br>${pgPct(result.confidence)}</p>
            <p><b>Phishing probability</b><br>${pgPct(result.phishing_probability)}</p>
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
    if (reportBtn) {
        reportBtn.addEventListener("click", async () => {
            reportBtn.disabled = true;
            reportBtn.textContent = "Reporting...";
            try {
                await fetch("http://127.0.0.1:8000/api/extension/report", {
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
                reportBtn.textContent = "Reported ✓";
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
