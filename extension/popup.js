document.addEventListener("DOMContentLoaded", async () => {
    const store = await chrome.storage.local.get([
        "lastScan",
        "historyConsentGiven",
    ]);

    document.getElementById("pg-consent-banner").style.display =
        store.historyConsentGiven ? "none" : "block";

    const result = document.getElementById("result");

    if (!store.lastScan) {
        result.innerHTML = `<p>No scan result available. Browse to a website to see PhishGuard's analysis.</p>`;
        return;
    }

    const scan = store.lastScan;
    const isPhishing = scan.prediction === "phishing";
    const isUncertain = scan.prediction === "uncertain";
    // A rule after the model decided the verdict (domain reputation / HTTPS
    // check), so the raw score is a URL-pattern score, not a probability of
    // the verdict shown.
    const overridden = ["reputable_domain", "https_only"].includes(scan.uncertain_reason)
        || scan.legit_reason === "http_reputable";
    const statusBadgeClass = isPhishing ? "danger" : isUncertain ? "risk-medium" : "safe";
    const statusText = isPhishing ? "PHISHING" : isUncertain ? "SUSPICIOUS" : "SAFE";
    const attack = scan.attack_type || {};
    const reasons = attack.indicators || [];

    result.innerHTML = `
        <div class="pg-row">
            <span class="pg-label">Website</span>
            <span class="pg-value">${pgEscape(scan.url)}</span>
        </div>
        <div class="pg-row">
            <span class="pg-label">Status</span>
            <span class="pg-value">
                <span class="pg-badge ${statusBadgeClass}">
                    ${statusText}
                </span>
            </span>
        </div>
        <div class="pg-row">
            <span class="pg-label">Risk Level</span>
            <span class="pg-value">
                <span class="pg-badge ${pgRiskBadgeClass(scan.risk_level)}">
                    ${pgEscape(scan.risk_level)}
                </span>
            </span>
        </div>
        ${overridden ? "" : `
        <div class="pg-row">
            <span class="pg-label">Confidence</span>
            <span class="pg-value">${pgPct(scan.confidence)}</span>
        </div>`}
        <div class="pg-row">
            <span class="pg-label">${overridden ? "URL Pattern Score" : "Phishing Probability"}</span>
            <span class="pg-value">${pgPct(scan.phishing_probability)}</span>
        </div>
        ${isPhishing ? `
        <div class="pg-row">
            <span class="pg-label">Attack Type</span>
            <span class="pg-value">${pgEscape(attack.category || "Unknown")}</span>
        </div>
        ` : ""}
        ${reasons.length ? `
            <div style="margin-top:10px;"><b>Detection Reasons</b></div>
            <ul class="pg-reasons">
                ${reasons.map((r) => `<li>${pgEscape(r)}</li>`).join("")}
            </ul>
        ` : ""}
        ${isPhishing ? `<div class="pg-recommendation">${pgEscape(pgRecommendation(attack.category))}</div>` : ""}
        ${isPhishing ? `<button class="pg-btn danger" id="report" style="margin-top:12px;">Report URL</button>` : ""}
    `;

    if (isPhishing) {
        document.getElementById("report").addEventListener("click", async (event) => {
            const btn = event.currentTarget;
            btn.disabled = true;
            btn.textContent = "Reporting...";
            try {
                await fetch("http://127.0.0.1:8000/api/extension/report", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", ...(await pgAuthHeaders()) },
                    body: JSON.stringify({
                        url: scan.url,
                        attack_type: attack.category || "Unknown",
                        detection_reason: "Reported from extension popup",
                        browser_info: navigator.userAgent,
                    }),
                });
                btn.textContent = "Reported ✓";
            } catch (error) {
                btn.textContent = "Report failed";
                btn.disabled = false;
            }
        });
    }
});
