from flask import Flask, render_template, jsonify
import json
import sys
from pathlib import Path

# =========================================================
# NETSAGE AI - DASHBOARD BACKEND + AI DIAGNOSIS
# =========================================================

app = Flask(__name__)

# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

# Add project root to Python path
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

RESULT_FILE = BASE_DIR / "checker_results.json"


# =========================================================
# IMPORT AI DIAGNOSIS ENGINE
# =========================================================

try:
    from ai.diagnosis_engine import build_diagnosis

    AI_ENGINE_AVAILABLE = True

except ImportError as error:

    print("WARNING: AI diagnosis engine could not be loaded.")
    print(error)

    AI_ENGINE_AVAILABLE = False


# =========================================================
# LOAD CHECKER RESULTS
# =========================================================

def load_results():

    if not RESULT_FILE.exists():
        return []

    try:

        with open(
            RESULT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):

        return []


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    return render_template("index.html")


# =========================================================
# ALL CASES
# =========================================================

@app.route("/api/cases")
def get_cases():

    results = load_results()

    cases = []

    for case in results:

        findings = case.get(
            "findings",
            []
        )

        cases.append({

            "case_id":
                case.get(
                    "case_id",
                    ""
                ),

            "finding_count":
                len(findings),

            "findings":
                findings

        })

    return jsonify(cases)


# =========================================================
# SINGLE CASE + AI DIAGNOSIS
# =========================================================

@app.route("/api/cases/<case_id>")
def get_case(case_id):

    results = load_results()

    for case in results:

        current_id = str(
            case.get(
                "case_id",
                ""
            )
        ).upper()

        if current_id == case_id.upper():

            findings = case.get(
                "findings",
                []
            )

            # ---------------------------------------------
            # Generate AI diagnosis
            # ---------------------------------------------

            if AI_ENGINE_AVAILABLE:

                diagnoses = build_diagnosis(
                    case
                )

            else:

                diagnoses = []

            return jsonify({

                "case_id":
                    case.get(
                        "case_id",
                        ""
                    ),

                "findings":
                    findings,

                "diagnoses":
                    diagnoses

            })

    return jsonify({
        "error": "Case not found"
    }), 404


# =========================================================
# DASHBOARD STATISTICS
# =========================================================

@app.route("/api/stats")
def get_stats():

    results = load_results()

    total_cases = len(
        results
    )

    cases_with_findings = 0

    total_findings = 0

    for case in results:

        findings = case.get(
            "findings",
            []
        )

        if findings:

            cases_with_findings += 1

        total_findings += len(
            findings
        )

    cases_without_findings = (
        total_cases
        - cases_with_findings
    )

    return jsonify({

        "total_cases":
            total_cases,

        "total_findings":
            total_findings,

        "cases_with_findings":
            cases_with_findings,

        "cases_without_findings":
            cases_without_findings,

        "ai_engine":
            AI_ENGINE_AVAILABLE

    })


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    print(
        "\n=========================================="
    )

    print(
        "       NETSAGE AI DASHBOARD"
    )

    print(
        "=========================================="
    )

    print(
        "\nAI Diagnosis Engine:",
        "AVAILABLE"
        if AI_ENGINE_AVAILABLE
        else "NOT AVAILABLE"
    )

    print(
        "\nOpen: http://127.0.0.1:5000"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )