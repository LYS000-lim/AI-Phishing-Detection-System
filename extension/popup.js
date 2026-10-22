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
    // The score on one scale for every verdict, always in the verdict's
    // band (backend score_view.py).
    const score = scan.score || {};
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
        ${score.confidence == null ? "" : `
        <div class="pg-row">
            <span class="pg-label">Confidence</span>
            <span class="pg-value">${pgPct(score.confidence)}</span>
        </div>`}
        <div class="pg-row">
            <span class="pg-label">Score</span>
            <span class="pg-value">${pgPct(score.risk_score)}</span>
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
