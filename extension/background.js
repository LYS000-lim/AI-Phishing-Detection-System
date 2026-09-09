const API_URL = "http://localhost:8000/api/extension/scan";


// Listen when a page finishes loading
chrome.webNavigation.onCompleted.addListener(
    async (details) => {

        // Only check main tab
        if (details.frameId !== 0) {
            return;
        }


        const url = details.url;


        // Ignore browser internal pages
        if (
            url.startsWith("chrome://") ||
            url.startsWith("chrome-extension://")
        ) {
            return;
        }


        console.log(
            "PhishGuard checking:",
            url
        );


        try {

            const response = await fetch(
                API_URL,
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );


            const result = await response.json();


            console.log(
                "PhishGuard result:",
                result
            );


            // Save latest result for popup
            chrome.storage.local.set({
                lastScan: result
            });


            // If phishing detected
            if (
                result.prediction === "phishing"
            ) {


                chrome.tabs.sendMessage(
                    details.tabId,
                    {
                        action: "SHOW_WARNING",
                        data: result
                    }
                );

            }


        }

        catch(error){

            console.error(
                "PhishGuard error:",
                error
            );

        }


    }
);