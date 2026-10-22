async function render() {
    const store = await chrome.storage.local.get([
        "detectionHistory",
        "historyRecordingEnabled",
    ]);

    const history = store.detectionHistory || [];
    const subtitle = document.getElementById("pg-history-subtitle");
    const list = document.getElementById("pg-history-list");

    if (!store.historyRecordingEnabled) {
        subtitle.textContent =
            "History recording is currently OFF — enable it in Settings to start recording.";
    } else {
        subtitle.textContent = `${history.length} site${history.length === 1 ? "" : "s"} checked`;
    }

    if (!history.length) {
        list.innerHTML = `<div class="pg-empty">No detection history yet.</div>`;
        return;
    }

    list.innerHTML = history
        .map((entry) => {
            const isPhishing = entry.prediction === "phishing";
            const isUncertain = entry.prediction === "uncertain";
            return `
                <div class="pg-history-item">
                    <div class="pg-url">${pgEscape(entry.url)}</div>
                    <div class="pg-meta">
                        <span class="pg-badge ${isPhishing ? "danger" : isUncertain ? "risk-medium" : "safe"}">
                            ${isPhishing ? "Phishing" : isUncertain ? "Suspicious" : "Legitimate"}
                        </span>
                        &nbsp;
                        <span class="pg-badge ${pgRiskBadgeClass(entry.risk_level)}">
                            ${pgEscape(entry.risk_level || "N/A")}
                        </span>
                        &nbsp;Score ${pgPct(entry.risk_score ?? null)}
                        ${entry.attack_type ? `&nbsp;&middot;&nbsp;${pgEscape(entry.attack_type)}` : ""}
                        &nbsp;&middot;&nbsp;${pgFormatTime(entry.time)}
                    </div>
                </div>
            `;
        })
        .join("");
}

render();
