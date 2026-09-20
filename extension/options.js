const BLOCKED_LIST_PREVIEW_LIMIT = 10;

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

async function renderBlockedList() {
    const store = await chrome.storage.local.get("userBlockedUrls");
    const list = (store.userBlockedUrls || []).slice().sort((a, b) => b.time - a.time);
    const container = document.getElementById("pg-blocked-list");
    const viewAllRow = document.getElementById("pg-view-all-row");

    if (!list.length) {
        container.className = "pg-empty";
        container.textContent = "No locally blocked URLs.";
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
renderBlockedList();
