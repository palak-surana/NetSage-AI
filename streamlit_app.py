import streamlit as st
import json
import sys
import textwrap
from pathlib import Path


def html(content):
    st.html(textwrap.dedent(content).strip())
# ============================================================
# NETSAGE AI - STREAMLIT FRONTEND
# ============================================================

st.set_page_config(
    page_title="NetSage AI",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

RESULT_FILE = BASE_DIR / "checker_results.json"

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


# ============================================================
# AI DIAGNOSIS ENGINE
# ============================================================

try:
    from ai.diagnosis_engine import build_diagnosis

    AI_AVAILABLE = True
    AI_ERROR = ""

except Exception as error:
    AI_AVAILABLE = False
    AI_ERROR = str(error)


# ============================================================
# LOAD CHECKER RESULTS
# ============================================================

@st.cache_data
def load_results():

    if not RESULT_FILE.exists():
        return []

    try:
        with open(
            RESULT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, list):
            return data

        return []

    except Exception:
        return []


results = load_results()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def confidence_to_number(confidence):
    """
    Convert AI confidence into a number between 0.0 and 1.0
    for Streamlit progress bar.
    """

    if confidence is None:
        return 0.0

    if isinstance(confidence, (int, float)):

        value = float(confidence)

        if value > 1:
            value = value / 100

        return max(0.0, min(1.0, value))

    text = str(confidence).strip().lower()

    try:
        if text.endswith("%"):
            value = float(text.replace("%", "").strip()) / 100
            return max(0.0, min(1.0, value))

        value = float(text)

        if value > 1:
            value = value / 100

        return max(0.0, min(1.0, value))

    except Exception:
        return 0.0


def get_case_by_id(case_id):

    for case in results:

        current_id = str(
            case.get("case_id", "")
        )

        if current_id.upper() == str(case_id).upper():
            return case

    return None


def run_ai_diagnosis(case):

    if not AI_AVAILABLE:
        return []

    try:
        diagnosis = build_diagnosis(case)

        if diagnosis is None:
            return []

        if isinstance(diagnosis, list):
            return diagnosis

        if isinstance(diagnosis, dict):
            return [diagnosis]

        return [diagnosis]

    except Exception as error:

        st.error(
            f"AI diagnosis error: {error}"
        )

        return []


# ============================================================
# SESSION STATE
# ============================================================

if "page" not in st.session_state:
    st.session_state.page = "Dashboard"

if "selected_case" not in st.session_state:
    st.session_state.selected_case = None


# ============================================================
# CUSTOM CSS
# ============================================================

html(
    """
    <style>

    /* --------------------------------------------------------
       MAIN APP
    -------------------------------------------------------- */

    .stApp {
        background: #f5f7fb;
    }


    .block-container {
        max-width: 1380px;
        padding-top: 3rem;
        padding-bottom: 4rem;
        padding-left: 2.2rem;
        padding-right: 2.2rem;
    }


    /* --------------------------------------------------------
       SIDEBAR
    -------------------------------------------------------- */

    [data-testid="stSidebar"] {
        background: #0f172a;
        border-right: 1px solid #1e293b;
    }

    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.8rem;
    }


    [data-testid="stSidebar"] * {
        color: #f8fafc;
    }

    [data-testid="stSidebar"] .stRadio > label {
        font-size: 13px;
        font-weight: 700;
        color: #94a3b8 !important;
        margin-bottom: 8px;
    }

    [data-testid="stSidebar"] .stRadio div[role="radiogroup"] {
        gap: 5px;
    }

    [data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label {
        background: transparent;
        border-radius: 10px;
        padding: 9px 10px;
        margin: 0;
        transition: 0.2s ease;
    }

    [data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:hover {
        background: #1e293b;
    }

    [data-testid="stSidebar"] .stCaption {
        color: #94a3b8 !important;
        font-size: 12px;
    }


    /* --------------------------------------------------------
       HERO
    -------------------------------------------------------- */

    .hero {
        background: linear-gradient(
            135deg,
            #0f172a 0%,
            #172554 48%,
            #2563eb 100%
        );

        padding: 42px 44px;

        border-radius: 26px;

        color: white;

        margin-bottom: 30px;

        box-shadow:
            0 12px 30px
            rgba(0, 0, 0, 0.12);
    }


    .hero-title {
        font-size: 44px;
        line-height: 1.1;
        font-weight: 850;
        margin-bottom: 10px;
        letter-spacing: -1px;
    }


    .hero-subtitle {
        font-size: 17px;
        opacity: 0.88;
        margin-bottom: 22px;
        max-width: 760px;
    }


    .status {
        display: inline-block;

        background: #16a34a;

        color: white;

        padding: 8px 15px;

        border-radius: 25px;

        font-size: 13px;

        font-weight: 700;
    }


    /* --------------------------------------------------------
       SECTION TITLE
    -------------------------------------------------------- */

    .section-title {
        font-size: 31px;
        line-height: 1.2;
        font-weight: 850;
        color: #0f172a;
        margin-top: 34px;
        margin-bottom: 10px;
        letter-spacing: -0.5px;
    }


    /* --------------------------------------------------------
       METRIC CARDS
    -------------------------------------------------------- */

    .metric-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 18px;
        padding: 22px;
        min-height: 130px;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
        transition: transform 0.2s ease, box-shadow 0.2s ease;

        box-shadow:
            0 5px 18px
            rgba(0, 0, 0, 0.06);
    }


    .metric-title {
        color: #64748b;

        font-size: 15px;

        font-weight: 600;
    }


    .metric-value {
        color: #172033;

        font-size: 36px;

        font-weight: 800;

        margin-top: 8px;
    }


    /* --------------------------------------------------------
       QUICK DIAGNOSIS
    -------------------------------------------------------- */

    .quick-card {
        background: white;

        border: 1px solid #e5e7eb;

        border-radius: 18px;

        padding: 25px;

        margin-top: 25px;

        box-shadow:
            0 5px 18px
            rgba(0, 0, 0, 0.05);
    }


    /* --------------------------------------------------------
       FAULT
    -------------------------------------------------------- */

    .fault-box {
        background: #fff7ed;

        border-left: 6px solid #f97316;

        border-radius: 16px;

        padding: 22px;

        margin: 20px 0;
    }


    /* --------------------------------------------------------
       SUCCESS
    -------------------------------------------------------- */

    .success-box {
        background: #f0fdf4;

        border-left: 6px solid #16a34a;

        border-radius: 16px;

        padding: 22px;

        margin: 20px 0;
    }


    /* --------------------------------------------------------
       INFO
    -------------------------------------------------------- */

    .info-box {
        background: #eff6ff;

        border-left: 6px solid #2563eb;

        border-radius: 16px;

        padding: 22px;

        margin: 20px 0;
    }


    /* --------------------------------------------------------
       DIAGNOSIS CARD
    -------------------------------------------------------- */

    .diagnosis-card {
        background: white;

        border: 1px solid #e5e7eb;

        border-radius: 18px;

        padding: 25px;

        margin: 20px 0;

        box-shadow:
            0 5px 18px
            rgba(0, 0, 0, 0.06);
    }


    .diagnosis-title {
        font-size: 24px;

        font-weight: 800;

        color: #172033;

        margin-bottom: 20px;
    }


    /* --------------------------------------------------------
       CASE CARD
    -------------------------------------------------------- */

    .case-card {
        background: white;

        border: 1px solid #e5e7eb;

        border-radius: 16px;

        padding: 20px;

        margin-bottom: 15px;
    }


    /* --------------------------------------------------------
       SIDEBAR STATUS
    -------------------------------------------------------- */

    .sidebar-status {
        background: linear-gradient(135deg, #123d35, #14532d);
        border: 1px solid rgba(74, 222, 128, 0.16);
        border-radius: 14px;
        padding: 16px;
        margin-top: 22px;
        color: white;
        box-shadow: 0 8px 22px rgba(0,0,0,0.12);
    }


    /* --------------------------------------------------------
       BUTTON
    -------------------------------------------------------- */

    .stButton > button {
        border-radius: 12px;
        min-height: 44px;
        font-weight: 800;
        border: 0;
        box-shadow: 0 6px 16px rgba(37, 99, 235, 0.18);
    }


    /* --------------------------------------------------------
       HIDE STREAMLIT BRANDING
    -------------------------------------------------------- */

    #MainMenu {
        visibility: hidden;
    }


    footer {
        visibility: hidden;
    }

    </style>
    """
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.markdown(
    """
    <div style="
        font-size:28px;
        font-weight:850;
        letter-spacing:-0.6px;
        margin-bottom:6px;
        color:#f8fafc;
    ">
        🧠 NetSage AI
    </div>
    <div style="
        font-size:12px;
        line-height:1.5;
        color:#94a3b8;
        margin-bottom:18px;
    ">
        AI-Assisted Network Troubleshooting
    </div>
    """,
    unsafe_allow_html=True
)


st.sidebar.markdown("---")


PAGES = [
    "Dashboard",
    "Diagnose Case",
    "Case Explorer",
    "About"
]


# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

page = st.sidebar.radio(
    "📌 Navigation",
    PAGES,
    index=PAGES.index(
        st.session_state.page
    )
)


if page != st.session_state.page:

    st.session_state.page = page

    st.rerun()


# ============================================================
# AI STATUS
# ============================================================

st.sidebar.markdown("---")


if AI_AVAILABLE:
    st.sidebar.markdown(
        """
        <div class="sidebar-status">
            <div style="font-size:13px;font-weight:800;margin-bottom:6px;">
                🟢 AI Diagnosis Engine
            </div>
            <div style="font-size:12px;color:#bbf7d0;">
                Available
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
else:
    st.sidebar.markdown(
        """
        <div class="sidebar-status" style="background:#3f1d1d;">
            <div style="font-size:13px;font-weight:800;margin-bottom:6px;">
                🔴 AI Diagnosis Engine
            </div>
            <div style="font-size:12px;color:#fecaca;">
                Offline
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# STATISTICS
# ============================================================

total_cases = len(results)


total_findings = sum(
    len(
        case.get(
            "findings",
            []
        )
    )
    for case in results
)


cases_with_faults = sum(
    1
    for case in results
    if case.get("findings", [])
)


cases_without_faults = (
    total_cases
    - cases_with_faults
)


# ============================================================
# HERO
# ============================================================

html(
    """
    <div class="hero">

        <div class="hero-title">
            🧠 NetSage AI
        </div>

        <div class="hero-subtitle">
            AI-Assisted Network Fault Diagnosis & Troubleshooting Platform
        </div>

        <div class="status">
            ● SYSTEM ONLINE
        </div>

    </div>
    """
)


# ============================================================
# DASHBOARD
# ============================================================

if page == "Dashboard":

    html(
        '<div class="section-title">📊 Network Overview</div>'
    )


    st.caption(
        "A one-glance summary of your network troubleshooting cases."
    )


    html("<br>")


    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    c1, c2, c3, c4 = st.columns(4)


    with c1:

        html(
            f"""
            <div class="metric-card">

                <div class="metric-title">
                    📁 Total Cases
                </div>

                <div class="metric-value">
                    {total_cases}
                </div>

            </div>
            """
        )


    with c2:

        html(
            f"""
            <div class="metric-card">

                <div class="metric-title">
                    🔴 Total Findings
                </div>

                <div class="metric-value">
                    {total_findings}
                </div>

            </div>
            """
        )


    with c3:

        html(
            f"""
            <div class="metric-card">

                <div class="metric-title">
                    🟢 Passed
                </div>

                <div class="metric-value">
                    {cases_without_faults}
                </div>

            </div>
            """
        )


    with c4:

        html(
            f"""
            <div class="metric-card">

                <div class="metric-title">
                    🟠 Need Review
                </div>

                <div class="metric-value">
                    {cases_with_faults}
                </div>

            </div>
            """
        )


    # --------------------------------------------------------
    # QUICK DIAGNOSIS
    # --------------------------------------------------------

    html(
        '<div class="section-title">🔎 Quick Diagnosis</div>'
    )


    html(
        """
        <div class="quick-card">

        <h3>
            🚀 Analyze a Network Case
        </h3>

        <p>
            Select a network case below and run the
            NetSage AI diagnosis engine.
        </p>

        <p>
            The selected case will be opened automatically
            in the detailed diagnosis page.
        </p>

        </div>
        """
    )


    if not results:

        st.warning(
            "No network cases found in checker_results.json."
        )

    else:

        case_ids = [
            str(
                case.get(
                    "case_id",
                    ""
                )
            )
            for case in results
        ]


        selected = st.selectbox(
            "Choose Network Case",
            case_ids,
            key="dashboard_case"
        )


        if st.button(
            "🚀 Analyze Network",
            type="primary",
            use_container_width=True
        ):

            st.session_state.selected_case = selected

            st.session_state.page = "Diagnose Case"

            st.rerun()


# ============================================================
# DIAGNOSE CASE
# ============================================================

elif page == "Diagnose Case":

    html(
        '<div class="section-title">🔎 AI Network Diagnosis</div>'
    )


    if not results:

        st.warning(
            "No network cases found."
        )

    else:

        case_ids = [
            str(
                case.get(
                    "case_id",
                    ""
                )
            )
            for case in results
        ]


        # ----------------------------------------------------
        # SELECT CASE
        # ----------------------------------------------------

        saved_case = st.session_state.selected_case


        if saved_case not in case_ids:

            saved_case = case_ids[0]


        selected_case = st.selectbox(
            "Choose Network Case",
            case_ids,
            index=case_ids.index(
                saved_case
            ),
            key="diagnose_case_select"
        )


        st.session_state.selected_case = selected_case


        # ----------------------------------------------------
        # FIND CASE
        # ----------------------------------------------------

        case = get_case_by_id(
            selected_case
        )


        if case is not None:

            findings = case.get(
                "findings",
                []
            )


            # ------------------------------------------------
            # CASE HEADER
            # ------------------------------------------------

            html(
                f"""
                <div class="case-card">

                    <h2>
                        Case
                        <span style="color:#16a34a;">
                            {selected_case}
                        </span>
                    </h2>

                </div>
                """
            )


            # ------------------------------------------------
            # FAULT STATUS
            # ------------------------------------------------

            if not findings:

                html(
                    """
                    <div class="success-box">

                        <h3>
                            🟢 No Fault Detected
                        </h3>

                        <p>
                            The automated rule-based checker
                            did not detect a network fault
                            in this case.
                        </p>

                    </div>
                    """
                )

            else:

                html(
                    f"""
                    <div class="fault-box">

                        <h3>
                            ⚠️ {len(findings)} Finding(s) Detected
                        </h3>

                        <p>
                            Rule-based network analysis identified
                            potential configuration issues.
                        </p>

                    </div>
                    """
                )


            # ------------------------------------------------
            # EVIDENCE
            # ------------------------------------------------

            st.markdown(
                "## 📋 Evidence & Findings"
            )


            if not findings:

                st.info(
                    "No findings are available."
                )

            else:

                for i, finding in enumerate(
                    findings,
                    start=1
                ):

                    with st.expander(
                        f"Finding {i}",
                        expanded=True
                    ):

                        if isinstance(
                            finding,
                            dict
                        ):

                            for key, value in finding.items():

                                title = (
                                    str(key)
                                    .replace(
                                        "_",
                                        " "
                                    )
                                    .title()
                                )


                                st.markdown(
                                    f"**{title}**"
                                )


                                st.write(
                                    value
                                )


                                st.markdown("---")

                        else:

                            st.write(
                                finding
                            )


            # ------------------------------------------------
            # AI DIAGNOSIS
            # ------------------------------------------------

            st.markdown(
                "## 🤖 AI Diagnosis"
            )


            if AI_AVAILABLE:

                diagnoses = run_ai_diagnosis(
                    case
                )


                if diagnoses:

                    for i, diagnosis in enumerate(
                        diagnoses,
                        start=1
                    ):

                        html(
                            f"""
                            <div class="diagnosis-card">

                                <div class="diagnosis-title">
                                    🤖 Diagnosis {i}
                                </div>

                            </div>
                            """
                        )


                        if isinstance(
                            diagnosis,
                            dict
                        ):

                            # --------------------------------
                            # CATEGORY
                            # --------------------------------

                            st.markdown(
                                "### 🏷️ Category"
                            )

                            st.write(
                                diagnosis.get(
                                    "category",
                                    "Unknown"
                                )
                            )


                            # --------------------------------
                            # SEVERITY
                            # --------------------------------

                            st.markdown(
                                "### ⚠️ Severity"
                            )


                            severity = diagnosis.get(
                                "severity",
                                "Unknown"
                            )


                            severity_text = str(
                                severity
                            ).lower()


                            if severity_text == "high":

                                st.error(
                                    str(severity)
                                )

                            elif severity_text == "medium":

                                st.warning(
                                    str(severity)
                                )

                            else:

                                st.info(
                                    str(severity)
                                )


                            # --------------------------------
                            # PROBLEM
                            # --------------------------------

                            st.markdown(
                                "### 🔴 Problem"
                            )

                            st.write(
                                diagnosis.get(
                                    "problem",
                                    "Not available"
                                )
                            )


                            # --------------------------------
                            # ROOT CAUSE
                            # --------------------------------

                            st.markdown(
                                "### 🎯 Root Cause"
                            )

                            st.write(
                                diagnosis.get(
                                    "root_cause",
                                    "Not available"
                                )
                            )


                            # --------------------------------
                            # EXPLANATION
                            # --------------------------------

                            st.markdown(
                                "### 💡 Explanation"
                            )

                            st.write(
                                diagnosis.get(
                                    "explanation",
                                    "Not available"
                                )
                            )


                            # --------------------------------
                            # RECOMMENDED FIX
                            # --------------------------------

                            st.markdown(
                                "### 🛠️ Recommended Resolution"
                            )

                            st.success(
                                diagnosis.get(
                                    "recommended_fix",
                                    "Not available"
                                )
                            )


                            # --------------------------------
                            # EVIDENCE
                            # --------------------------------

                            st.markdown(
                                "### 🔎 Evidence"
                            )

                            st.info(
                                diagnosis.get(
                                    "evidence",
                                    "Not available"
                                )
                            )


                            # --------------------------------
                            # CONFIDENCE
                            # --------------------------------

                            st.markdown(
                                "### 📈 Confidence"
                            )


                            confidence = diagnosis.get(
                                "confidence",
                                "N/A"
                            )


                            confidence_value = (
                                confidence_to_number(
                                    confidence
                                )
                            )


                            st.progress(
                                confidence_value
                            )


                            st.write(
                                f"Confidence: {confidence}"
                            )


                        else:

                            st.write(
                                diagnosis
                            )


                        st.markdown("---")


                else:

                    st.info(
                        "The AI engine did not produce a diagnosis."
                    )

            else:

                st.error(
                    "AI diagnosis engine is unavailable."
                )

                st.code(
                    AI_ERROR
                )


# ============================================================
# CASE EXPLORER
# ============================================================

elif page == "Case Explorer":

    html(
        '<div class="section-title">📋 Case Explorer</div>'
    )


    st.caption(
        "Browse and inspect all network troubleshooting cases."
    )


    search = st.text_input(
        "🔎 Search Case ID"
    ).strip().upper()


    filtered_cases = results


    if search:

        filtered_cases = [

            case

            for case in results

            if search in str(
                case.get(
                    "case_id",
                    ""
                )
            ).upper()

        ]


    st.write(
        f"Showing **{len(filtered_cases)}** case(s)"
    )


    if not filtered_cases:

        st.warning(
            "No matching cases found."
        )


    for case in filtered_cases:

        case_id = case.get(
            "case_id",
            "UNKNOWN"
        )


        findings = case.get(
            "findings",
            []
        )


        if findings:

            status = "🔴 FAULT"

        else:

            status = "🟢 PASS"


        with st.expander(
            f"{case_id}   |   {status}"
        ):

            st.write(
                f"**Number of Findings:** {len(findings)}"
            )


            if findings:

                for i, finding in enumerate(
                    findings,
                    start=1
                ):

                    st.markdown(
                        f"### Finding {i}"
                    )


                    if isinstance(
                        finding,
                        dict
                    ):

                        for key, value in finding.items():

                            title = (
                                str(key)
                                .replace(
                                    "_",
                                    " "
                                )
                                .title()
                            )


                            st.write(
                                f"**{title}:**",
                                value
                            )

                    else:

                        st.write(
                            finding
                        )

            else:

                st.success(
                    "No findings detected."
                )


# ============================================================
# ABOUT
# ============================================================

elif page == "About":

    html(
        '<div class="section-title">ℹ️ About NetSage AI</div>'
    )


    st.markdown(
        """
        ## 🧠 NetSage AI

        NetSage AI is an intelligent network
        troubleshooting platform designed to analyze
        network evidence and identify configuration
        problems.


        ## 🔄 Diagnosis Pipeline

        **📡 Network Evidence**

        ↓

        **🔍 Rule-Based Checker**

        ↓

        **🤖 AI Diagnosis Engine**

        ↓

        **🎯 Root Cause Analysis**

        ↓

        **🛠️ Recommended Resolution**


        ## 🚀 Core Features

        - Network case analysis
        - Rule-based fault detection
        - AI-assisted diagnosis
        - Evidence inspection
        - Case explorer
        - Network troubleshooting workflow
        - Interactive Streamlit dashboard


        ## 📡 Technology

        - Python
        - Streamlit
        - Flask backend
        - JSON
        - Network rule engine
        - AI diagnosis engine


        ## 🎯 Project Goal

        NetSage AI combines deterministic network
        checking with AI-assisted reasoning to help
        identify network faults and explain possible
        root causes.
        """
    )


# ============================================================
# FOOTER
# ============================================================

html(
    """
    <br>
    <hr>

    <div style="
        text-align:center;
        color:#64748b;
        font-size:13px;
        padding:15px;
    ">

        NetSage AI • Intelligent Network Troubleshooting Platform

    </div>
    """
)