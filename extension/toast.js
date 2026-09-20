// Small, non-blocking "safe" notification for legitimate scans (both
// ML-classified and trusted-allowlist results). Built with inline styles
// (not style.css) so it never depends on / clashes with the host page's own
// stylesheet, and with DOM methods (not innerHTML) so the scanned URL is
// never parsed as markup.
//
// Registered as a document_start content script so the runtime.onMessage
// listener below is live as early as possible — background.js pushes the
// toast data the moment the scan finishes, which can race ahead of a fast
// page's load. The pull request below is the fallback for the reverse race
// (push arriving before this script had attached its listener).

chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "SHOW_SAFE_TOAST" && message.data) {
        showSafeToast(message.data);
    }
});

(async () => {
    if (!location.href.startsWith("http")) {
        return;
    }

    // Trusted-allowlist domains (google.com etc.) are exactly the sites most
    // likely to already be DNS-cached/preconnected and finish loading in a
    // handful of milliseconds — faster than background.js's chain of
    // (blacklist check + scan) network round-trips plus chrome.storage
    // calls, especially right after an MV3 service-worker cold start. A
    // single one-shot pull can lose that race consistently for exactly
    // those fast sites, so retry briefly instead of checking once.
    const data = await pollForSafeToast();
    if (data) {
        showSafeToast(data);
    }
})();

async function pollForSafeToast(maxAttempts = 10, intervalMs = 200) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
            const data = await chrome.runtime.sendMessage({ action: "GET_SAFE_TOAST" });
            if (data) {
                return data;
            }
        } catch (error) {
            return null; // extension context gone (page navigating away)
        }
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    return null;
}

function showSafeToast(data) {
    const attach = () => {
        if (document.getElementById("phishguard-safe-toast") || !document.documentElement) {
            return;
        }

        const el = document.createElement("div");
        el.id = "phishguard-safe-toast";
        el.style.cssText = [
            "position:fixed",
            "bottom:20px",
            "right:20px",
            "z-index:2147483647",
            "background:#111827",
            "color:#e5e7eb",
            "border:1px solid #22c55e",
            "border-radius:10px",
            "padding:14px 18px",
            "font-family:Arial,Helvetica,sans-serif",
            "font-size:13px",
            "line-height:1.5",
            "box-shadow:0 4px 20px rgba(0,0,0,0.4)",
            "max-width:280px",
            "opacity:0",
            "transition:opacity 0.3s ease",
        ].join(";");

        const title = document.createElement("div");
        title.textContent = "✓ Website Scanned";
        title.style.cssText = "font-weight:bold;color:#4ade80;margin-bottom:8px;";
        el.appendChild(title);

        const rows = [
            ["Website", data.url],
            ["Status", "Safe"],
            ["Verification", data.verification || "AI Detection Model"],
        ];

        for (const [label, value] of rows) {
            const row = document.createElement("div");
            row.style.cssText = "word-break:break-word;";

            const labelEl = document.createElement("span");
            labelEl.textContent = `${label}: `;
            labelEl.style.cssText = "color:#94a3b8;";

            const valueEl = document.createElement("span");
            valueEl.textContent = value;

            row.appendChild(labelEl);
            row.appendChild(valueEl);
            el.appendChild(row);
        }

        document.documentElement.appendChild(el);

        requestAnimationFrame(() => {
            el.style.opacity = "1";
        });

        setTimeout(() => {
            el.style.opacity = "0";
            setTimeout(() => el.remove(), 350);
        }, 4000);
    };

    if (document.documentElement) {
        attach();
    } else {
        document.addEventListener("DOMContentLoaded", attach, { once: true });
    }
}
