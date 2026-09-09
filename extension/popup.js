document.addEventListener(
    "DOMContentLoaded",
    () => {


        chrome.storage.local.get(
            [
                "lastScan"
            ],

            (data)=>{


                const result =
                document.getElementById(
                    "result"
                );


                if(!data.lastScan){

                    result.innerHTML = `

                    <p>
                    No scan result available.
                    </p>

                    `;

                    return;

                }


                const scan =
                data.lastScan;



                const isPhishing =
                scan.prediction === "phishing";



                result.innerHTML = `


                <p>
                <b>Website:</b>
                <br>
                ${scan.url}
                </p>


                <p>
                <b>Status:</b>
                <br>

                <span class="
                ${isPhishing ? 
                "danger" : 
                "safe"}
                ">

                ${
                    isPhishing
                    ?
                    "⚠ PHISHING"
                    :
                    "✓ SAFE"
                }

                </span>

                </p>


                <p>
                <b>Risk:</b>
                ${scan.risk_level}
                </p>



                <p>
                <b>Confidence:</b>

                ${
                    (scan.confidence*100)
                    .toFixed(2)
                }%

                </p>



                ${
                isPhishing
                ?

                `

                <p>
                <b>Attack:</b>

                ${
                    scan.attack_type?.category
                    ||
                    "Unknown"
                }

                </p>


                <button
                id="report">
                    Report URL
                </button>

                `

                :

                ""

                }


                `;



                if(isPhishing){

                    document
                    .getElementById(
                        "report"
                    )
                    .onclick =
                    async()=>{


                        await fetch(

                        "http://localhost:8000/api/extension/report",

                        {

                        method:"POST",

                        headers:{
                        "Content-Type":
                        "application/json"
                        },


                        body:
                        JSON.stringify({

                        url:scan.url,

                        attack_type:
                        scan.attack_type?.category
                        ||
                        "Unknown",


                        detection_reason:
                        "Reported from extension popup",


                        browser_info:
                        navigator.userAgent

                        })

                        }

                        );


                        alert(
                        "URL reported"
                        );


                    };

                }


            }

        );


    }

);