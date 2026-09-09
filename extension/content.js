chrome.runtime.onMessage.addListener(
    (message) => {


        if (
            message.action === "SHOW_WARNING"
        ) {

            showWarning(
                message.data
            );

        }


    }
);



function showWarning(data){


    // Prevent duplicate warning
    if (
        document.getElementById(
            "phishguard-warning"
        )
    ){
        return;
    }



    // Hide existing page
    document.documentElement.innerHTML = "";



    const container =
        document.createElement("div");


    container.id =
        "phishguard-warning";



    container.innerHTML = `

        <div class="pg-card">


            <h1>
                ⚠️ PhishGuard AI
            </h1>


            <h2>
                Dangerous Website Detected
            </h2>



            <p>
                This website may be a phishing attempt.
            </p>



            <div class="pg-info">

                <p>
                    <b>Website:</b>
                    <br>
                    ${data.url}
                </p>


                <p>
                    <b>Risk Level:</b>
                    <br>
                    ${data.risk_level}
                </p>



                <p>
                    <b>Confidence:</b>
                    <br>
                    ${(data.confidence * 100).toFixed(2)}%
                </p>



                <p>
                    <b>Attack Type:</b>
                    <br>
                    ${
                        data.attack_type?.category
                        ||
                        "Unknown"
                    }
                </p>


            </div>



            <button id="pg-leave">
                Leave Website
            </button>


            <button id="pg-continue">
                Continue Anyway
            </button>


            <button id="pg-report">
                Report URL
            </button>



        </div>

    `;



    document.body.appendChild(
        container
    );



    // Leave website
    document
    .getElementById(
        "pg-leave"
    )
    .onclick = () => {

        window.location.href =
        "https://www.google.com";

    };



    // Continue
    document
    .getElementById(
        "pg-continue"
    )
    .onclick = () => {

        document.documentElement.innerHTML =
        "";

        window.location.reload();

    };



    // Report
    document
    .getElementById(
        "pg-report"
    )
    .onclick = async()=>{


        await fetch(
            "http://localhost:8000/api/extension/report",
            {

                method:"POST",

                headers:{
                    "Content-Type":
                    "application/json"
                },


                body:JSON.stringify({

                    url:data.url,

                    attack_type:
                    data.attack_type?.category
                    ||
                    "Unknown",


                    detection_reason:
                    "Reported from PhishGuard Chrome Extension",


                    browser_info:
                    navigator.userAgent

                })

            }

        );


        alert(
            "URL reported successfully"
        );


    };


}