import json
from pathlib import Path


# =========================================================
# NETSAGE AI - DIAGNOSIS ENGINE
# =========================================================

RESULT_FILE = Path("checker_results.json")


# =========================================================
# FAULT KNOWLEDGE BASE
# =========================================================

FAULT_KNOWLEDGE = {

    "VLAN Configuration": {
        "severity": "High",
        "explanation": "The device or switch port has an incorrect VLAN configuration.",
        "fix": "Verify the VLAN exists and configure the affected switch port with the correct VLAN."
    },

    "VLAN/Trunk": {
        "severity": "High",
        "explanation": "The required VLAN is not being carried correctly across the trunk.",
        "fix": "Verify the trunk configuration and add the required VLAN to the allowed VLAN list."
    },

    "VLAN/802.1Q": {
        "severity": "High",
        "explanation": "The 802.1Q VLAN ID configured on the interface does not match the expected VLAN.",
        "fix": "Correct the encapsulation dot1Q VLAN ID on the router subinterface."
    },

    "Native VLAN": {
        "severity": "High",
        "explanation": "The native VLAN configuration differs between trunk endpoints.",
        "fix": "Configure the same native VLAN on both ends of the trunk."
    },

    "Gateway": {
        "severity": "High",
        "explanation": "The host has an incorrect or missing default gateway.",
        "fix": "Configure the correct default gateway for the host subnet."
    },

    "DHCP": {
        "severity": "High",
        "explanation": "The DHCP configuration is preventing clients from receiving or correctly using network parameters.",
        "fix": "Verify the DHCP pool, subnet mask, default-router and available addresses."
    },

    "DNS": {
        "severity": "Medium",
        "explanation": "The configured DNS server or DNS resolution process is incorrect.",
        "fix": "Verify the DNS server address and test name resolution using nslookup."
    },

    "Routing": {
        "severity": "High",
        "explanation": "The required network route is missing or incorrectly configured.",
        "fix": "Check the routing table and configure the correct static or dynamic route."
    },

    "ACL": {
        "severity": "High",
        "explanation": "An access-control rule is blocking required network traffic.",
        "fix": "Review the ACL entries, source/destination addresses, protocol and ports, then correct the rule."
    },

    "NAT": {
        "severity": "High",
        "explanation": "Network Address Translation is incorrectly configured or missing.",
        "fix": "Verify inside/outside interfaces and NAT or static NAT mappings."
    },

    "Duplicate IP": {
        "severity": "Critical",
        "explanation": "More than one device appears to be using the same IP address.",
        "fix": "Identify the conflicting devices and assign unique IP addresses."
    },

    "Interface Status": {
        "severity": "High",
        "explanation": "A network interface is down or administratively disabled.",
        "fix": "Check the interface status, cabling and configuration. Use no shutdown where appropriate."
    },

    "Physical Link": {
        "severity": "High",
        "explanation": "The network evidence indicates a physical link or cabling problem.",
        "fix": "Check the Ethernet cable, connectors, switch port and interface error counters."
    },

    "Speed/Duplex": {
        "severity": "Medium",
        "explanation": "The interface speed or duplex configuration does not match the expected configuration.",
        "fix": "Configure matching speed and duplex settings on both connected interfaces."
    },

    "Wireless": {
        "severity": "Medium",
        "explanation": "The wireless configuration or radio environment is causing connectivity problems.",
        "fix": "Verify the wireless security settings and check channel utilization and interference."
    }
}


# =========================================================
# DEFAULT KNOWLEDGE
# =========================================================

DEFAULT_KNOWLEDGE = {
    "severity": "Medium",
    "explanation": "A network configuration or connectivity problem was detected.",
    "fix": "Review the network configuration and verify the affected device and connectivity."
}


# =========================================================
# CONFIDENCE
# =========================================================

def calculate_confidence(finding):
    """
    Calculate a simple deterministic confidence score.
    """

    rule = str(finding.get("rule", "")).strip()
    message = str(finding.get("message", "")).strip()

    if rule and message:
        return 95

    if rule:
        return 85

    return 70


# =========================================================
# BUILD DIAGNOSIS
# =========================================================

def build_diagnosis(case):
    """
    Convert checker findings into human-readable diagnosis.
    """

    findings = case.get("findings", [])

    diagnoses = []

    for finding in findings:

        rule = str(
            finding.get("rule", "Unknown")
        ).strip()

        message = str(
            finding.get("message", "Network fault detected.")
        ).strip()

        knowledge = FAULT_KNOWLEDGE.get(
            rule,
            DEFAULT_KNOWLEDGE
        )

        confidence = calculate_confidence(
            finding
        )

        diagnoses.append({

            "category": rule,

            "severity": knowledge["severity"],

            "problem": message,

            "explanation": knowledge["explanation"],

            "recommended_fix": knowledge["fix"],

            "confidence": f"{confidence}%"

        })

    return diagnoses


# =========================================================
# LOAD RESULTS
# =========================================================

def load_results():

    if not RESULT_FILE.exists():

        print(
            "ERROR: checker_results.json not found."
        )

        print(
            "Run rule_checker.py first."
        )

        return []

    try:

        with open(
            RESULT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError:

        print(
            "ERROR: checker_results.json contains invalid JSON."
        )

        return []


# =========================================================
# DISPLAY
# =========================================================

def display_diagnosis(case):

    case_id = case.get(
        "case_id",
        "UNKNOWN"
    )

    diagnoses = build_diagnosis(case)

    print("\n==========================================")

    print(
        f"NETSAGE AI DIAGNOSIS - {case_id}"
    )

    print("==========================================")

    if not diagnoses:

        print("\nOK: No fault detected.")

        return

    for index, diagnosis in enumerate(
        diagnoses,
        start=1
    ):

        print(
            f"\nFinding {index}"
        )

        print(
            f"Category        : "
            f"{diagnosis['category']}"
        )

        print(
            f"Severity        : "
            f"{diagnosis['severity']}"
        )

        print(
            f"Problem         : "
            f"{diagnosis['problem']}"
        )

        print(
            f"Explanation     : "
            f"{diagnosis['explanation']}"
        )

        print(
            f"Recommended Fix : "
            f"{diagnosis['recommended_fix']}"
        )

        print(
            f"Confidence      : "
            f"{diagnosis['confidence']}"
        )


# =========================================================
# MAIN
# =========================================================

def main():

    results = load_results()

    if not results:
        return

    print(
        "\nNetSage AI Diagnosis Engine"
    )

    print(
        "============================"
    )

    case_id = input(
        "\nEnter Case ID "
        "(example CASE002): "
    ).strip().upper()

    selected_case = None

    for case in results:

        if str(
            case.get("case_id", "")
        ).upper() == case_id:

            selected_case = case

            break

    if selected_case is None:

        print(
            f"\nERROR: {case_id} not found."
        )

        return

    display_diagnosis(
        selected_case
    )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()