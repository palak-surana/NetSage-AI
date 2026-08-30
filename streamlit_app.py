import streamlit as st
import json
import sys
from pathlib import Path
from html import escape

# ============================================================
# NETSAGE AI - STREAMLIT FRONTEND
# ============================================================

st.set_page_config(
    page_title="NetSage AI",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# PATHS
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
# DATA
# ============================================================

@st.cache_data(ttl=3)
def load_results():
    if not RESULT_FILE.exists():
        return []

    try:
        with RESULT_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, list) else []
    except Exception:
        return []


results = load_results()


def get_case_by_id(case_id):
    target = str(case_id).upper()

    for case in results:
        if str(case.get("case_id", "")).upper() == target:
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
        st.error(f"AI diagnosis error: {error}")
        return []


def confidence_to_number(confidence):
    if confidence is None:
        return 0.0

    if isinstance(confidence, (int, float)):
        value = float(confidence)
    else:
        text = str(confidence).strip().lower().replace(",", "")
        try:
            if text.endswith("%"):
                value = float(text[:-1]) / 100
            else:
                value = float(text)
        except Exception:
            return 0.0

    if value > 1:
        value /= 100

    return max(0.0, min(1.0, value))


def first_value(data, *keys, default="Not available"):
    if not isinstance(data, dict):
        return default

    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]

    return default


def format_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, ensure_ascii=False)
    return str(value)


def get_packet_tracer_evidence(case_id):
    """
    Verified Packet Tracer evidence currently mapped to CASE001.

    CASE001 was checked manually in netsage_network.pkt:
    Switch0 Fa0/2 is the PC0 access port and is currently in VLAN 1.
    The expected VLAN for the case is VLAN 10.
    """
    evidence_map = {
        "CASE001": {
            "device": "Switch0",
            "interface": "FastEthernet0/2",
            "connection": "PC0 ↔ Switch0",
            "switchport_mode": "Static access",
            "current_vlan": "1",
            "expected_vlan": "10",
            "status": "MISMATCH DETECTED",
            "command": "show interfaces fa0/2 switchport",
            "source_file": "packet_tracer/netsage_network.pkt",
        }
    }

    return evidence_map.get(str(case_id).upper())


def finding_summary(finding):
    if isinstance(finding, dict):
        rule = first_value(finding, "rule", "category", "type", default="Network Finding")
        status = first_value(finding, "status", "result", default="Review")
        message = first_value(
            finding,
            "message",
            "description",
            "finding",
            "details",
            default="Configuration issue detected.",
        )
        return str(rule), str(status), str(message)

    return "Network Finding", "FAIL", str(finding)


# ============================================================
# SESSION STATE
# ============================================================

if "page" not in st.session_state:
    st.session_state.page = "Dashboard"

if "selected_case" not in st.session_state:
    st.session_state.selected_case = None

if "ai_cache" not in st.session_state:
    st.session_state.ai_cache = {}


# ============================================================
# GLOBAL CSS
# ============================================================

st.markdown(
    """
<style>
/* ---------- GLOBAL ---------- */
.stApp {
    background:
        radial-gradient(circle at 90% 0%, rgba(37,99,235,.08), transparent 28%),
        #f4f7fb;
    color: #172033;
}

.block-container {
    max-width: 1440px;
    padding-top: 2.2rem;
    padding-bottom: 4rem;
    padding-left: 2.4rem;
    padding-right: 2.4rem;
}

h1, h2, h3, h4 {
    color: #172033 !important;
}

/* ---------- SIDEBAR ---------- */
[data-testid="stSidebar"] {
    background: #0b1220;
    border-right: 1px solid #1d2a3d;
}

[data-testid="stSidebar"] > div:first-child {
    padding-top: 1.4rem;
}

[data-testid="stSidebar"] * {
    color: #f8fafc;
}

[data-testid="stSidebar"] .stRadio > label {
    color: #94a3b8 !important;
    font-size: 12px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: .08em;
    margin-bottom: 10px;
}

[data-testid="stSidebar"] .stRadio div[role="radiogroup"] {
    gap: 5px;
}

[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label {
    border-radius: 12px;
    padding: 10px 11px;
    transition: all .18s ease;
}

[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:hover {
    background: #172235;
}

.sidebar-brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 27px;
    font-weight: 900;
    letter-spacing: -.7px;
    color: white;
}

.sidebar-subtitle {
    color: #8fa0b7;
    font-size: 12px;
    line-height: 1.5;
    margin-top: 6px;
}

.sidebar-status {
    margin-top: 22px;
    padding: 15px;
    border-radius: 15px;
    background: linear-gradient(135deg, #0f3d34, #075e46);
    border: 1px solid rgba(74,222,128,.18);
    box-shadow: 0 10px 25px rgba(0,0,0,.16);
}

.sidebar-status.offline {
    background: linear-gradient(135deg, #451a1a, #7f1d1d);
}

/* ---------- HERO ---------- */
.hero {
    position: relative;
    overflow: hidden;
    background: linear-gradient(135deg, #0b1220 0%, #172554 48%, #2563eb 100%);
    border-radius: 28px;
    padding: 42px 44px;
    margin-bottom: 32px;
    color: white;
    box-shadow: 0 20px 45px rgba(15,23,42,.16);
}

.hero::after {
    content: "";
    position: absolute;
    width: 320px;
    height: 320px;
    right: -90px;
    top: -150px;
    border-radius: 50%;
    background: rgba(255,255,255,.08);
}

.hero-title {
    position: relative;
    z-index: 1;
    font-size: 46px;
    font-weight: 900;
    letter-spacing: -1.5px;
    line-height: 1.05;
}

.hero-subtitle {
    position: relative;
    z-index: 1;
    margin-top: 12px;
    color: #dbeafe;
    font-size: 17px;
    max-width: 820px;
}

.status-pill {
    position: relative;
    z-index: 1;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    margin-top: 24px;
    padding: 9px 15px;
    border-radius: 999px;
    background: #16a34a;
    color: white;
    font-size: 12px;
    font-weight: 900;
    letter-spacing: .04em;
}

/* ---------- PAGE HEADERS ---------- */
.page-head {
    margin: 8px 0 20px;
}

.page-head h1 {
    margin: 0;
    font-size: 31px;
    font-weight: 900;
    letter-spacing: -.7px;
}

.page-head p {
    margin: 7px 0 0;
    color: #64748b;
    font-size: 14px;
}

/* ---------- METRICS ---------- */
.metric-card {
    background: white;
    border: 1px solid #e4eaf2;
    border-radius: 18px;
    padding: 21px;
    min-height: 142px;
    box-shadow: 0 8px 25px rgba(15,23,42,.055);
}

.metric-top {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #64748b;
    font-size: 13px;
    font-weight: 800;
}

.metric-value {
    margin-top: 9px;
    color: #172033;
    font-size: 38px;
    font-weight: 900;
    letter-spacing: -1px;
}

.metric-note {
    margin-top: 4px;
    color: #94a3b8;
    font-size: 12px;
}

/* ---------- CARDS ---------- */
.panel {
    background: white;
    border: 1px solid #e3e9f1;
    border-radius: 20px;
    padding: 25px;
    margin-top: 22px;
    box-shadow: 0 8px 26px rgba(15,23,42,.055);
}

.panel-title {
    font-size: 19px;
    font-weight: 900;
    color: #172033;
    margin-bottom: 5px;
}

.panel-subtitle {
    color: #64748b;
    font-size: 13px;
    margin-bottom: 18px;
}

/* ---------- CASE HEADER ---------- */
.case-banner {
    background: linear-gradient(135deg, #ffffff, #f8fbff);
    border: 1px solid #dce5f0;
    border-radius: 20px;
    padding: 24px 26px;
    margin-top: 20px;
    box-shadow: 0 8px 24px rgba(15,23,42,.05);
}

.case-id {
    color: #2563eb;
    font-size: 27px;
    font-weight: 900;
}

.case-label {
    color: #64748b;
    font-size: 12px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: .08em;
}

/* ---------- ALERTS ---------- */
.alert {
    border-radius: 18px;
    padding: 20px 22px;
    margin: 20px 0;
}

.alert-fault {
    background: #fff7ed;
    border: 1px solid #fed7aa;
    border-left: 6px solid #f97316;
}

.alert-success {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-left: 6px solid #16a34a;
}

.alert-info {
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-left: 6px solid #2563eb;
}

.alert-title {
    font-size: 17px;
    font-weight: 900;
}

.alert-text {
    margin-top: 5px;
    color: #64748b;
    font-size: 13px;
}

/* ---------- FINDING ---------- */
.finding-card {
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 17px;
    padding: 20px;
    margin-bottom: 13px;
}

.finding-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 15px;
}

.finding-rule {
    font-size: 16px;
    font-weight: 900;
    color: #172033;
}

.badge-fail {
    background: #fee2e2;
    color: #b91c1c;
    padding: 5px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 900;
}

.badge-pass {
    background: #dcfce7;
    color: #15803d;
    padding: 5px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 900;
}

.finding-message {
    margin-top: 13px;
    padding: 13px 14px;
    border-radius: 12px;
    background: #f8fafc;
    color: #475569;
    font-size: 13px;
    line-height: 1.55;
}

/* ---------- AI ---------- */
.ai-card {
    background: linear-gradient(135deg, #ffffff, #f8fbff);
    border: 1px solid #dbe5f1;
    border-radius: 20px;
    padding: 24px;
    margin: 17px 0;
    box-shadow: 0 10px 28px rgba(37,99,235,.06);
}

.ai-title {
    font-size: 20px;
    font-weight: 900;
    color: #172033;
    margin-bottom: 18px;
}

.ai-label {
    color: #64748b;
    font-size: 11px;
    font-weight: 900;
    text-transform: uppercase;
    letter-spacing: .08em;
    margin-top: 14px;
    margin-bottom: 5px;
}

.ai-value {
    color: #172033;
    font-size: 14px;
    line-height: 1.6;
}

.fix-box {
    background: #ecfdf5;
    border: 1px solid #bbf7d0;
    border-radius: 13px;
    padding: 14px;
    color: #166534;
    font-size: 14px;
    line-height: 1.55;
}

/* ---------- TABLE / EXPLORER ---------- */
.explorer-card {
    background: white;
    border: 1px solid #e3e9f1;
    border-radius: 17px;
    padding: 17px 19px;
    margin-bottom: 11px;
}

/* ---------- BUTTONS ---------- */
.stButton > button {
    border-radius: 12px;
    min-height: 43px;
    font-weight: 800;
    border: 1px solid #dbe3ee;
}

.stButton > button[kind="primary"] {
    border: 0;
}

/* ---------- SELECTBOX ---------- */
[data-baseweb="select"] > div {
    border-radius: 12px;
    border-color: #dbe3ee;
}

/* ---------- HIDE STREAMLIT BRANDING ---------- */
#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

/* ---------- MOBILE ---------- */
@media (max-width: 900px) {
    .block-container {
        padding-left: 1rem;
        padding-right: 1rem;
    }

    .hero {
        padding: 30px 25px;
    }

    .hero-title {
        font-size: 36px;
    }
}
</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.markdown(
    """
    <div class="sidebar-brand">🧠 NetSage AI</div>
    <div class="sidebar-subtitle">
        AI-Assisted Network Troubleshooting
    </div>
    """,
    unsafe_allow_html=True,
)

st.sidebar.markdown("---")

PAGES = ["Dashboard", "Diagnose Case", "Case Explorer", "About"]

page = st.sidebar.radio(
    "Navigation",
    PAGES,
    index=PAGES.index(st.session_state.page),
)

if page != st.session_state.page:
    st.session_state.page = page
    st.rerun()

st.sidebar.markdown("---")

if AI_AVAILABLE:
    st.sidebar.markdown(
        """
        <div class="sidebar-status">
            <div style="font-weight:900;font-size:13px;">🟢 AI Diagnosis Engine</div>
            <div style="color:#bbf7d0;font-size:12px;margin-top:5px;">
                Online & available
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    st.sidebar.markdown(
        """
        <div class="sidebar-status offline">
            <div style="font-weight:900;font-size:13px;">🔴 AI Diagnosis Engine</div>
            <div style="color:#fecaca;font-size:12px;margin-top:5px;">
                Offline
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# STATISTICS
# ============================================================

total_cases = len(results)

total_findings = sum(
    len(case.get("findings", []))
    for case in results
    if isinstance(case, dict)
)

fault_cases = sum(
    1
    for case in results
    if isinstance(case, dict) and case.get("findings", [])
)

passed_cases = sum(
    1
    for case in results
    if isinstance(case, dict) and not case.get("findings", [])
)

review_cases = 0

# Count issue types from the actual rule-checker findings.
issue_type_counts = {}

for case in results:
    if not isinstance(case, dict):
        continue

    for finding in case.get("findings", []):
        if isinstance(finding, dict):
            rule_name = str(
                finding.get(
                    "rule",
                    finding.get(
                        "category",
                        finding.get("type", "Other")
                    )
                )
            ).strip()

            if not rule_name:
                rule_name = "Other"
        else:
            rule_name = "Other"

        issue_type_counts[rule_name] = (
            issue_type_counts.get(rule_name, 0) + 1
        )


# ============================================================
# TOP HERO
# ============================================================

st.markdown(
    """
    <div class="hero">
        <div class="hero-title">🧠 NetSage AI</div>
        <div class="hero-subtitle">
            AI-Assisted Network Fault Diagnosis & Troubleshooting Platform
        </div>
        <div class="status-pill">● SYSTEM ONLINE</div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# DASHBOARD
# ============================================================

if page == "Dashboard":

    st.markdown(
        """
        <div class="page-head">
            <h1>📊 Network Overview</h1>
            <p>Monitor cases, findings and troubleshooting activity at a glance.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-top">📁 TOTAL CASES</div>
                <div class="metric-value">{total_cases}</div>
                <div class="metric-note">Cases available for analysis</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-top">🔴 TOTAL FINDINGS</div>
                <div class="metric-value">{total_findings}</div>
                <div class="metric-note">Issues detected by checker</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-top">🟢 PASSED</div>
                <div class="metric-value">{passed_cases}</div>
                <div class="metric-note">Cases with no findings</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-top">🔴 FAULTS DETECTED</div>
                <div class="metric-value">{fault_cases}</div>
                <div class="metric-note">Cases with detected network faults</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # --------------------------------------------------------
    # NETWORK ISSUE TYPES
    # --------------------------------------------------------

    st.markdown(
        """
        <div class="page-head" style="margin-top:32px;">
            <h1>📊 Network Issue Types</h1>
            <p>Distribution of detected problems by rule/checker type.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if issue_type_counts:
        st.bar_chart(
            issue_type_counts,
            height=340,
        )

        # Small numeric summary below the chart.
        sorted_issue_types = sorted(
            issue_type_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )

        summary_cols = st.columns(
            min(4, len(sorted_issue_types))
        )

        for index, (issue_type, count) in enumerate(sorted_issue_types):
            with summary_cols[index % len(summary_cols)]:
                st.markdown(
                    f"""
                    <div class="panel" style="margin-top:10px;padding:16px;">
                        <div style="
                            font-size:12px;
                            font-weight:800;
                            color:#64748b;
                        ">
                            {issue_type}
                        </div>
                        <div style="
                            font-size:28px;
                            font-weight:900;
                            color:#172033;
                            margin-top:3px;
                        ">
                            {count}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
    else:
        st.info("No issue types are available to chart yet.")

    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">🚀 Quick Diagnosis</div>
            <div class="panel-subtitle">
                Select a case and open the AI-assisted diagnosis workflow.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not results:
        st.warning("No network cases found in checker_results.json.")
    else:
        case_ids = [
            str(case.get("case_id", ""))
            for case in results
            if case.get("case_id")
        ]

        selected = st.selectbox(
            "Choose a network case",
            case_ids,
            key="dashboard_case",
        )

        col_a, col_b = st.columns([1, 3])

        with col_a:
            if st.button(
                "🔎 Analyze Case",
                type="primary",
                use_container_width=True,
            ):
                st.session_state.selected_case = selected
                st.session_state.page = "Diagnose Case"
                st.rerun()

        with col_b:
            st.info(
                "The rule checker provides deterministic findings; "
                "the AI engine explains the likely root cause and recommended resolution."
            )

    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">🧭 Troubleshooting Pipeline</div>
            <div class="panel-subtitle">
                How NetSage AI processes a network case.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    p1, p2, p3, p4 = st.columns(4)

    pipeline = [
        ("01", "📡", "Evidence", "Network evidence is collected."),
        ("02", "🔍", "Rule Checker", "Known faults are detected."),
        ("03", "🤖", "AI Diagnosis", "The finding is interpreted."),
        ("04", "🛠️", "Resolution", "A practical fix is suggested."),
    ]

    for col, (num, icon, title, desc) in zip([p1, p2, p3, p4], pipeline):
        with col:
            st.markdown(
                f"""
                <div class="panel" style="margin-top:12px;min-height:155px;">
                    <div style="color:#2563eb;font-size:11px;font-weight:900;">
                        {num}
                    </div>
                    <div style="font-size:25px;margin-top:8px;">{icon}</div>
                    <div style="font-size:16px;font-weight:900;margin-top:7px;">
                        {title}
                    </div>
                    <div style="font-size:12px;color:#64748b;margin-top:5px;">
                        {desc}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ============================================================
# DIAGNOSE CASE
# ============================================================

elif page == "Diagnose Case":

    st.markdown(
        """
        <div class="page-head">
            <h1>🔎 AI Network Diagnosis</h1>
            <p>Inspect rule-based findings and generate an AI-assisted explanation.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not results:
        st.warning("No network cases found.")
    else:
        case_ids = [
            str(case.get("case_id", ""))
            for case in results
            if case.get("case_id")
        ]

        saved_case = st.session_state.selected_case

        if saved_case not in case_ids:
            saved_case = case_ids[0]

        selected_case = st.selectbox(
            "Choose network case",
            case_ids,
            index=case_ids.index(saved_case),
            key="diagnose_case_select",
        )

        st.session_state.selected_case = selected_case

        case = get_case_by_id(selected_case)

        if case is not None:
            findings = case.get("findings", [])
            evidence = case.get("evidence", None)

            st.markdown(
                f"""
                <div class="case-banner">
                    <div class="case-label">Selected Network Case</div>
                    <div class="case-id">{escape(selected_case)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if findings:
                st.markdown(
                    f"""
                    <div class="alert alert-fault">
                        <div class="alert-title">⚠️ {len(findings)} Finding(s) Detected</div>
                        <div class="alert-text">
                            The rule-based checker identified potential network
                            configuration or connectivity issues.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    """
                    <div class="alert alert-success">
                        <div class="alert-title">🟢 No Fault Detected</div>
                        <div class="alert-text">
                            The rule-based checker did not detect a fault in this case.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # ----------------------------------------------------
            # PACKET TRACER EVIDENCE
            # ----------------------------------------------------

            packet_evidence = get_packet_tracer_evidence(selected_case)

            st.markdown(
                """
                <div class="page-head" style="margin-top:28px;">
                    <h1>📡 Packet Tracer Evidence</h1>
                    <p>
                        Network configuration evidence linked to the selected
                        Cisco Packet Tracer case.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if packet_evidence:
                e1, e2, e3, e4 = st.columns(4)

                evidence_items = [
                    ("Device", packet_evidence["device"]),
                    ("Interface", packet_evidence["interface"]),
                    ("Mode", packet_evidence["switchport_mode"]),
                    ("Current VLAN", packet_evidence["current_vlan"]),
                ]

                for column, (label, value) in zip(
                    [e1, e2, e3, e4],
                    evidence_items,
                ):
                    with column:
                        st.markdown(
                            f"""
                            <div class="metric-card" style="min-height:112px;">
                                <div class="metric-top">{escape(label.upper())}</div>
                                <div style="
                                    margin-top:8px;
                                    font-size:20px;
                                    font-weight:900;
                                    color:#172033;
                                ">
                                    {escape(value)}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                st.markdown(
                    f"""
                    <div class="alert alert-fault" style="margin-top:16px;">
                        <div class="alert-title">
                            🔴 {escape(packet_evidence["status"])}
                        </div>
                        <div class="alert-text">
                            Current VLAN <b>{escape(packet_evidence["current_vlan"])}</b>
                            does not match expected VLAN
                            <b>{escape(packet_evidence["expected_vlan"])}</b>
                            for this case.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                with st.expander("🔎 View Packet Tracer verification details"):
                    st.markdown(
                        f"""
                        **Source:** `{escape(packet_evidence["source_file"])}`

                        **Connection:** {escape(packet_evidence["connection"])}

                        **CLI command used:** `{escape(packet_evidence["command"])}`

                        **Current VLAN:** `{escape(packet_evidence["current_vlan"])}`

                        **Expected VLAN:** `{escape(packet_evidence["expected_vlan"])}`
                        """
                    )

                    st.info(
                        "This evidence was verified manually in Cisco Packet Tracer "
                        "from the Switch0 CLI configuration."
                    )
            else:
                st.info(
                    "Packet Tracer evidence is not mapped for this case yet. "
                    "The rule-checker evidence and AI diagnosis are still available."
                )

            # ----------------------------------------------------
            # FINDINGS
            # ----------------------------------------------------

            st.markdown(
                """
                <div class="page-head">
                    <h1>📋 Evidence & Findings</h1>
                    <p>Detailed output returned by the deterministic rule checker.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if not findings:
                st.info("No findings are available for this case.")
            else:
                for index, finding in enumerate(findings, start=1):
                    rule, status, message = finding_summary(finding)

                    status_upper = status.upper()
                    badge_class = (
                        "badge-pass"
                        if status_upper in {"PASS", "PASSED", "OK"}
                        else "badge-fail"
                    )

                    st.markdown(
                        f"""
                        <div class="finding-card">
                            <div class="finding-head">
                                <div class="finding-rule">
                                    Finding {index} · {escape(rule)}
                                </div>
                                <div class="{badge_class}">
                                    {escape(status_upper)}
                                </div>
                            </div>
                            <div class="finding-message">
                                {escape(message)}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    if isinstance(finding, dict):
                        with st.expander("View complete finding data"):
                            st.json(finding)

            if evidence:
                with st.expander("📡 View raw case evidence"):
                    st.write(evidence)

            # ----------------------------------------------------
            # AI DIAGNOSIS
            # ----------------------------------------------------

            st.markdown(
                """
                <div class="page-head" style="margin-top:35px;">
                    <h1>🤖 AI Diagnosis</h1>
                    <p>AI-assisted interpretation of the detected network issue.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if not AI_AVAILABLE:
                st.error("AI diagnosis engine is unavailable.")
                with st.expander("View AI import error"):
                    st.code(AI_ERROR)
            else:
                cache_key = str(selected_case)

                if cache_key not in st.session_state.ai_cache:
                    if st.button(
                        "🤖 Run AI Diagnosis",
                        type="primary",
                        use_container_width=True,
                    ):
                        with st.spinner("Analyzing network evidence..."):
                            st.session_state.ai_cache[cache_key] = run_ai_diagnosis(case)
                        st.rerun()
                else:
                    diagnoses = st.session_state.ai_cache[cache_key]

                    if st.button(
                        "🔄 Re-run AI Diagnosis",
                        use_container_width=True,
                    ):
                        with st.spinner("Running diagnosis again..."):
                            st.session_state.ai_cache[cache_key] = run_ai_diagnosis(case)
                        st.rerun()

                    if not diagnoses:
                        st.info("The AI engine did not produce a diagnosis for this case.")
                    else:
                        for index, diagnosis in enumerate(diagnoses, start=1):

                            # Use native Streamlit components here.
                            # This avoids raw HTML appearing as code blocks.
                            with st.container(border=True):
                                st.subheader(f"🤖 Diagnosis {index}")

                                if not isinstance(diagnosis, dict):
                                    st.write(diagnosis)
                                    continue

                                category = first_value(
                                    diagnosis,
                                    "category",
                                    "type",
                                    "rule",
                                    default="Network Issue",
                                )

                                severity = first_value(
                                    diagnosis,
                                    "severity",
                                    default="Unknown",
                                )

                                problem = first_value(
                                    diagnosis,
                                    "problem",
                                    "issue",
                                    "finding",
                                    default="Not available",
                                )

                                root_cause = first_value(
                                    diagnosis,
                                    "root_cause",
                                    "rootCause",
                                    default="Not available",
                                )

                                explanation = first_value(
                                    diagnosis,
                                    "explanation",
                                    "reason",
                                    default="Not available",
                                )

                                fix = first_value(
                                    diagnosis,
                                    "recommended_fix",
                                    "recommended_resolution",
                                    "resolution",
                                    "fix",
                                    default="Not available",
                                )

                                ai_evidence = first_value(
                                    diagnosis,
                                    "evidence",
                                    "supporting_evidence",
                                    default="Not available",
                                )

                                confidence = first_value(
                                    diagnosis,
                                    "confidence",
                                    default="N/A",
                                )

                                # Category
                                st.markdown("**🏷️ Category**")
                                st.write(category)

                                # Severity
                                st.markdown("**⚠️ Severity**")
                                severity_text = str(severity).strip().lower()

                                if severity_text == "critical":
                                    st.error(f"🔴 Critical — {severity}")
                                elif severity_text == "high":
                                    st.error(f"🟠 High — {severity}")
                                elif severity_text == "medium":
                                    st.warning(f"🟡 Medium — {severity}")
                                elif severity_text == "low":
                                    st.success(f"🟢 Low — {severity}")
                                else:
                                    st.info(str(severity))

                                # Problem
                                st.markdown("**🔴 Problem**")
                                st.write(problem)

                                # Root cause
                                st.markdown("**🎯 Root Cause**")
                                st.write(root_cause)

                                # Explanation
                                st.markdown("**💡 Explanation**")
                                st.write(explanation)

                                # Recommended resolution
                                st.markdown("**🛠️ Recommended Resolution**")
                                st.success(str(fix))

                                # Evidence
                                st.markdown("**🔎 Evidence**")
                                st.info(str(ai_evidence))

                                # Confidence
                                confidence_value = confidence_to_number(confidence)
                                st.markdown(f"**📈 AI Confidence: {confidence}**")
                                st.progress(confidence_value)


# ============================================================
# CASE EXPLORER
# ============================================================

elif page == "Case Explorer":

    st.markdown(
        """
        <div class="page-head">
            <h1>📋 Case Explorer</h1>
            <p>Search and inspect all network troubleshooting cases.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    search = st.text_input(
        "🔎 Search by Case ID or Finding",
        placeholder="Example: CASE001 or VLAN",
    ).strip().upper()

    filtered_cases = []

    for case in results:
        case_id = str(case.get("case_id", "")).upper()
        findings_text = json.dumps(
            case.get("findings", []),
            ensure_ascii=False,
        ).upper()

        if not search or search in case_id or search in findings_text:
            filtered_cases.append(case)

    st.caption(f"Showing {len(filtered_cases)} of {total_cases} case(s)")

    if not filtered_cases:
        st.warning("No matching cases found.")
    else:
        for case in filtered_cases:
            case_id = str(case.get("case_id", "UNKNOWN"))
            findings = case.get("findings", [])
            status = "🔴 FAULT" if findings else "🟢 PASS"

            with st.expander(f"{case_id}  ·  {status}  ·  {len(findings)} finding(s)"):
                if findings:
                    for index, finding in enumerate(findings, start=1):
                        rule, finding_status, message = finding_summary(finding)

                        st.markdown(
                            f"""
                            <div class="explorer-card">
                                <b>Finding {index}</b><br>
                                <span style="color:#64748b;">{escape(rule)}</span>
                                <div style="margin-top:8px;color:#475569;">
                                    {escape(message)}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                else:
                    st.success("No findings detected.")

                if st.button(
                    f"Open {case_id}",
                    key=f"open_{case_id}",
                    use_container_width=True,
                ):
                    st.session_state.selected_case = case_id
                    st.session_state.page = "Diagnose Case"
                    st.rerun()


# ============================================================
# ABOUT
# ============================================================

elif page == "About":

    st.markdown(
        """
        <div class="page-head">
            <h1>ℹ️ About NetSage AI</h1>
            <p>
                Intelligent network troubleshooting with deterministic checks
                and AI assistance.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### 🧠 What is NetSage AI?")

    st.write(
        "NetSage AI is a network troubleshooting platform designed to "
        "analyze network evidence, detect configuration problems and "
        "explain likely root causes."
    )

    st.markdown("### 🔄 Diagnosis Pipeline")

    p1, p2, p3, p4, p5 = st.columns(5)

    pipeline = [
        ("📡", "Network Evidence"),
        ("🔍", "Rule-Based Checker"),
        ("🤖", "AI Diagnosis"),
        ("🎯", "Root Cause"),
        ("🛠️", "Resolution"),
    ]

    for col, (icon, label) in zip([p1, p2, p3, p4, p5], pipeline):
        with col:
            st.markdown(
                f"""
                <div class="panel" style="
                    margin-top:10px;
                    min-height:120px;
                    text-align:center;
                ">
                    <div style="font-size:26px;">{icon}</div>
                    <div style="
                        margin-top:8px;
                        font-weight:800;
                        font-size:13px;
                    ">
                        {label}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("### 🚀 Core Features")

    f1, f2 = st.columns(2)

    with f1:
        st.markdown(
            """
            <div class="panel" style="margin-top:10px;">
                <div style="line-height:2;">
                    ✓ Network case analysis<br>
                    ✓ Rule-based fault detection<br>
                    ✓ AI-assisted diagnosis<br>
                    ✓ Evidence inspection
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with f2:
        st.markdown(
            """
            <div class="panel" style="margin-top:10px;">
                <div style="line-height:2;">
                    ✓ Case explorer<br>
                    ✓ Troubleshooting workflow<br>
                    ✓ Interactive Streamlit dashboard<br>
                    ✓ Recommended resolution
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### ⚙️ Technology")

    st.info(
        "Python · Streamlit · Flask · JSON · Network Rule Engine · "
        "AI Diagnosis Engine"
    )



# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div style="
        text-align:center;
        color:#94a3b8;
        font-size:12px;
        padding:35px 10px 10px;
    ">
        NetSage AI • Intelligent Network Troubleshooting Platform
    </div>
    """,
    unsafe_allow_html=True,
)
