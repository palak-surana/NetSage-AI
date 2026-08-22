// =========================================================
// NETSAGE AI DASHBOARD
// =========================================================


// =========================================================
// LOAD STATISTICS
// =========================================================

async function loadStats() {

    try {

        const response =
            await fetch("/api/stats");

        const data =
            await response.json();

        document.getElementById(
            "totalCases"
        ).textContent =
            data.total_cases;

        document.getElementById(
            "totalFindings"
        ).textContent =
            data.total_findings;

        document.getElementById(
            "casesWithFindings"
        ).textContent =
            data.cases_with_findings;

        document.getElementById(
            "casesWithoutFindings"
        ).textContent =
            data.cases_without_findings;

    }

    catch (error) {

        console.error(
            "Failed to load statistics:",
            error
        );

    }
}


// =========================================================
// LOAD CASES
// =========================================================

async function loadCases() {

    try {

        const response =
            await fetch("/api/cases");

        const cases =
            await response.json();

        const select =
            document.getElementById(
                "caseSelect"
            );

        cases.forEach(caseData => {

            const option =
                document.createElement(
                    "option"
                );

            option.value =
                caseData.case_id;

            option.textContent =
                caseData.case_id +
                " (" +
                caseData.finding_count +
                " finding(s))";

            select.appendChild(
                option
            );

        });

    }

    catch (error) {

        console.error(
            "Failed to load cases:",
            error
        );

    }
}


// =========================================================
// ANALYZE CASE
// =========================================================

async function analyzeCase() {

    const caseId =
        document.getElementById(
            "caseSelect"
        ).value;

    const result =
        document.getElementById(
            "result"
        );


    if (!caseId) {

        result.innerHTML = `

            <h2>Diagnosis</h2>

            <p class="empty">
                Please select a case first.
            </p>

        `;

        return;
    }


    // Loading state

    result.innerHTML = `

        <h2>Diagnosis - ${caseId}</h2>

        <p class="empty">
            🧠 NetSage AI is analyzing the case...
        </p>

    `;


    try {

        const response =
            await fetch(
                "/api/cases/" + caseId
            );

        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Unable to load case."
            );

        }


        // =================================================
        // NO FINDING
        // =================================================

        if (
            !data.diagnoses ||
            data.diagnoses.length === 0
        ) {

            result.innerHTML = `

                <h2>
                    Diagnosis - ${data.case_id}
                </h2>

                <div class="ok">

                    <h3>
                        ✅ No deterministic fault detected
                    </h3>

                    <p>
                        NetSage AI did not identify
                        a known network fault in this case.
                    </p>

                </div>

            `;

            return;
        }


        // =================================================
        // BUILD AI DIAGNOSIS
        // =================================================

        let html = `

            <h2>
                🧠 AI Diagnosis - ${data.case_id}
            </h2>

            <p class="ai-status">
                NetSage AI analyzed
                ${data.diagnoses.length}
                finding(s).
            </p>

        `;


        data.diagnoses.forEach(
            (diagnosis, index) => {

                html += `

                    <div class="ai-diagnosis">

                        <div class="diagnosis-header">

                            <div>

                                <span class="fault-number">
                                    Finding ${index + 1}
                                </span>

                                <h3>
                                    ❌ ${diagnosis.category}
                                </h3>

                            </div>

                            <span class="severity">
                                ${diagnosis.severity}
                            </span>

                        </div>


                        <div class="diagnosis-section">

                            <h4>
                                🔴 Problem
                            </h4>

                            <p>
                                ${diagnosis.problem}
                            </p>

                        </div>


                        <div class="diagnosis-section">

                            <h4>
                                💡 Why this happened
                            </h4>

                            <p>
                                ${diagnosis.explanation}
                            </p>

                        </div>


                        <div class="diagnosis-section fix">

                            <h4>
                                🔧 Recommended Fix
                            </h4>

                            <p>
                                ${diagnosis.recommended_fix}
                            </p>

                        </div>


                        <div class="confidence">

                            <span>
                                AI Confidence
                            </span>

                            <strong>
                                ${diagnosis.confidence}
                            </strong>

                        </div>

                    </div>

                `;

            }
        );


        result.innerHTML = html;

    }

    catch (error) {

        console.error(error);

        result.innerHTML = `

            <h2>Diagnosis</h2>

            <div class="error">

                ❌ Unable to analyze case.

                <br><br>

                ${error.message}

            </div>

        `;

    }
}


// =========================================================
// INITIALIZE DASHBOARD
// =========================================================

loadStats();

loadCases();