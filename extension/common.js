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
        "Brand Impersonation":
            "Verify you are on the brand's official domain before entering any information.",
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

// PhishGuard website (frontend dev server), where blocks are unblocked.
const PG_WEBSITE_URL = "http://localhost:5173";

function pgRiskMeaning(risk) {
    const r = (risk || "").toLowerCase();
    if (r === "high") return "Strong evidence of phishing. Do not visit or enter any information.";
    if (r === "medium") return "Several phishing signs were found. Treat this website as unsafe.";
    return "Few warning signs, but the website was still blocked.";
}

// Plain-language description of each attack category (phishing_type.py).
function pgAttackDescription(category) {
    const map = {
        "Credential Theft":
            "A fake sign-in page built to capture your username and password.",
        "Financial Scam":
            "Imitates a bank, payment or billing page to steal card or banking details.",
        "Fake Giveaway / Scam":
            "Promises prizes, rewards or free items to trick you into sharing data or paying a fee.",
        "Tech Support / Malware Scam":
            "Shows fake security alerts or downloads to install malware or get you to call scammers.",
        "Brand Impersonation":
            "Uses a well-known brand name, or a look-alike spelling of it, on a domain the brand does not own.",
        "General Phishing":
            "The address looks like phishing but does not match one specific attack type.",
        "Domain Spoofing / Brand Impersonation":
            "Uses a well-known brand name on a domain the brand does not own, to look trustworthy.",
    };
    return map[category] || "A website designed to trick visitors into giving away information.";
}
