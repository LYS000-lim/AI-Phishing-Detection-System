async function render() {
    const store = await chrome.storage.local.get("userBlockedUrls");
    const list = (store.userBlockedUrls || [])
        .slice()
        .sort((a, b) => b.time - a.time);

    const subtitle = document.getElementById("pg-blocked-subtitle");
    const container = document.getElementById("pg-blocked-full-list");

    subtitle.textContent = `${list.length} URL${list.length === 1 ? "" : "s"} blocked`;

    if (!list.length) {
        container.innerHTML = `<div class="pg-empty">No locally blocked URLs.</div>`;
        return;
    }

    container.innerHTML = list
        .map(
            (entry, index) => `
                <div class="pg-history-item">
                    <div class="pg-url">${index + 1}. ${pgEscape(entry.url)}</div>
                    <div class="pg-meta">Time: ${pgFormatTime(entry.time)}</div>
                </div>
            `
        )
        .join("");
}

render();
