// Shared helpers used by popup.js, warning.js, options.js and history.js.

function pgRecommendation(category) {
    const map = {
        "Credential Theft":
            "Do not enter your username or password on this site.",
        "Financial Scam":
            "Do not enter any payment or banking information.",
        "Fake Giveaway / Scam":
            "Do not provide personal information or make any payment.",
        "Tech Support / Malware Scam":
            "Do not download or install anything from this site, and do not call any phone number shown.",
        "Domain Spoofing / Brand Impersonation":
            "Verify you are on the brand's official domain before entering any information.",
    };
    return (
        map[category] ||
        "Avoid entering any personal or account information on this website."
    );
}

function pgPct(value) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) {
        return "N/A";
    }
    return `${(Number(value) * 100).toFixed(1)}%`;
}

function pgEscape(str) {
    const div = document.createElement("div");
    div.textContent = str ?? "";
    return div.innerHTML;
}

function pgRiskBadgeClass(risk) {
    const r = (risk || "").toLowerCase();
    if (r === "high") return "risk-high";
    if (r === "medium") return "risk-medium";
    return "risk-low";
}

function pgFormatTime(ms) {
    try {
        return new Date(ms).toLocaleString();
    } catch (error) {
        return "";
    }
}

// Authorization header for the signed-in website account (if any), so
// reports made from extension pages are attributed to that user.
async function pgAuthHeaders() {
    const auth = await chrome.storage.session.get("pgAuthToken");
    return auth.pgAuthToken ? { Authorization: `Bearer ${auth.pgAuthToken}` } : {};
}
