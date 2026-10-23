const PG_PAGE_SIZE = 10;
let pgPage = 1;

async function render() {
    const store = await chrome.storage.local.get([
        "detectionHistory",
        "historyRecordingEnabled",
    ]);

    const history = store.detectionHistory || [];
    const subtitle = document.getElementById("pg-history-subtitle");
    const list = document.getElementById("pg-history-list");
    const pager = document.getElementById("pg-history-pager");

    if (!store.historyRecordingEnabled) {
        subtitle.textContent =
            "History recording is currently OFF — enable it in Settings to start recording.";
    } else {
        subtitle.textContent = `${history.length} site${history.length === 1 ? "" : "s"} checked`;
    }

    if (!history.length) {
        list.innerHTML = `<div class="pg-empty">No detection history yet.</div>`;
        pager.hidden = true;
        return;
    }

    const totalPages = Math.ceil(history.length / PG_PAGE_SIZE);
    pgPage = Math.min(Math.max(pgPage, 1), totalPages);
    const start = (pgPage - 1) * PG_PAGE_SIZE;

    list.innerHTML = history
        .slice(start, start + PG_PAGE_SIZE)
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

    pager.hidden = totalPages <= 1;
    document.getElementById("pg-page-info").textContent =
        `Page ${pgPage} of ${totalPages} (${start + 1}–${Math.min(start + PG_PAGE_SIZE, history.length)} of ${history.length})`;
    document.getElementById("pg-prev").disabled = pgPage === 1;
    document.getElementById("pg-next").disabled = pgPage === totalPages;
}

function pgGoTo(page) {
    pgPage = page;
    render();
    window.scrollTo(0, 0);
}

document.getElementById("pg-prev").addEventListener("click", () => pgGoTo(pgPage - 1));
document.getElementById("pg-next").addEventListener("click", () => pgGoTo(pgPage + 1));

render();
