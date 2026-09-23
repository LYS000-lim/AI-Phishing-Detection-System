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
        renderBlocked(card, data, tabId);
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

function renderBlocked(card, data, tabId) {
    card.innerHTML = `
        <h1>&#9940; PhishGuard AI</h1>
        <h2>Website Blocked</h2>

        <div class="pg-blocked-banner">
            This website was previously blocked due to phishing risk.
        </div>

        <div class="pg-info">
            <p><b>Website:</b><br>${pgEscape(data.url)}</p>
            <p><b>Reason:</b><br>${pgEscape(data.reason || "Confirmed phishing domain.")}</p>
        </div>

        <div class="pg-recommendation">Do not continue to this website.</div>

        <button id="pg-continue">Continue Access</button>
        <button id="pg-leave">Go Back</button>
        <button id="pg-report">Report URL</button>
    `;

    wireButtons(data.url, null, tabId);
}

function renderWarning(card, data, tabId) {
    const result = data.result || {};
    const attack = result.attack_type || {};
    const reasons = attack.indicators || [];

    card.innerHTML = `
        <h1>&#9888;&#65039; PhishGuard AI</h1>
        <h2>Dangerous Website Detected</h2>
        <p>This website may be a phishing attempt.</p>

        <div class="pg-info">
            <p><b>Website:</b><br>${pgEscape(result.url || data.url)}</p>
            <p><b>Risk Level:</b><br>
                <span class="pg-badge ${pgRiskBadgeClass(result.risk_level)}">
                    ${pgEscape(result.risk_level || "Unknown")}
                </span>
            </p>
            <p><b>Confidence:</b><br>${pgPct(result.confidence)}</p>
            <p><b>Phishing Probability:</b><br>${pgPct(result.phishing_probability)}</p>
            <p><b>Attack Type:</b><br>${pgEscape(attack.category || "Unknown")}</p>
            ${reasons.length ? `
                <p><b>Detection Reasons:</b></p>
                <ul class="pg-reasons">
                    ${reasons.map((r) => `<li>${pgEscape(r)}</li>`).join("")}
                </ul>
            ` : ""}
        </div>

        <div class="pg-recommendation">${pgEscape(pgRecommendation(attack.category))}</div>

        <button id="pg-continue">Continue Access</button>
        <button id="pg-leave">Go Back</button>
        <button id="pg-report">Report URL</button>
        <button id="pg-block">Block URL</button>
    `;

    wireButtons(result.url || data.url, attack.category || null, tabId);
}

function wireButtons(url, attackCategory, tabId) {
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
                        detection_reason: "Reported from PhishGuard warning page",
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
            });
            blockBtn.textContent = "Blocked ✓";
        });
    }
}

init();
