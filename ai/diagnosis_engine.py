import json
from pathlib import Path


# =========================================================
# NETSAGE AI - DIAGNOSIS ENGINE V2
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent
RESULT_FILE = BASE_DIR / "checker_results.json"


# =========================================================
# FAULT KNOWLEDGE BASE V2
# =========================================================

FAULT_KNOWLEDGE = {

    "VLAN Configuration": {
        "severity": "High",
        "root_cause": "The switch port is assigned to the wrong VLAN or the required VLAN is not configured.",
        "explanation": "The VLAN configuration does not match the expected network design.",
        "fix": "Verify that the VLAN exists and assign the affected switch port to the correct VLAN."
    },

    "VLAN/Trunk": {
        "severity": "High",
        "root_cause": "The required VLAN is not allowed across the trunk link.",
        "explanation": "Trunk endpoints are not carrying all required VLAN traffic.",
        "fix": "Check the trunk configuration and add the required VLAN to the allowed VLAN list."
    },

    "VLAN/802.1Q": {
        "severity": "High",
        "root_cause": "The router subinterface is configured with the wrong 802.1Q VLAN ID.",
        "explanation": "The VLAN tag does not match the expected VLAN.",
        "fix": "Configure the correct encapsulation dot1Q VLAN ID on the router subinterface."
    },

    "Native VLAN": {
        "severity": "High",
        "root_cause": "The native VLAN is different on the two trunk endpoints.",
        "explanation": "A native VLAN mismatch can cause unexpected traffic handling across the trunk.",
        "fix": "Configure the same native VLAN on both ends of the trunk."
    },

    "Gateway": {
        "severity": "High",
        "root_cause": "The host is using an incorrect or missing default gateway.",
        "explanation": "The default gateway is required for communication outside the local subnet.",
        "fix": "Configure the correct default gateway for the host subnet."
    },

    "DHCP": {
        "severity": "High",
        "root_cause": "The DHCP service or pool is incorrectly configured or has no available addresses.",
        "explanation": "Clients may fail to obtain valid IP configuration from DHCP.",
        "fix": "Verify the DHCP pool, subnet mask, default-router and available addresses."
    },

    "DNS": {
        "severity": "Medium",
        "root_cause": "The DNS server configuration or DNS resolution process is incorrect.",
        "explanation": "Incorrect DNS configuration prevents clients from resolving domain names.",
        "fix": "Verify the DNS server address and test name resolution using nslookup."
    },

    "Routing": {
        "severity": "High",
        "root_cause": "A required network route is missing or incorrectly configured.",
        "explanation": "The router does not have the correct path to the destination network.",
        "fix": "Check the routing table and configure the correct static or dynamic route."
    },

    "ACL": {
        "severity": "High",
        "root_cause": "An access-control rule is blocking or incorrectly permitting required traffic.",
        "explanation": "ACL rules determine which network traffic is allowed or denied.",
        "fix": "Review source, destination, protocol, ports and ACL order, then correct the rule."
    },

    "NAT": {
        "severity": "High",
        "root_cause": "Network Address Translation is missing or incorrectly configured.",
        "explanation": "Incorrect NAT prevents private addresses from being translated correctly.",
        "fix": "Verify inside/outside interfaces and NAT or static NAT mappings."
    },

    "Duplicate IP": {
        "severity": "Critical",
        "root_cause": "Two or more network devices appear to be using the same IP address.",
        "explanation": "Duplicate IP addresses can cause intermittent or complete network connectivity problems.",
        "fix": "Identify the conflicting devices and assign unique IP addresses."
    },

    "Interface Status": {
        "severity": "High",
        "root_cause": "The network interface is down or administratively disabled.",
        "explanation": "A disabled interface cannot forward normal network traffic.",
        "fix": "Check the interface status, cabling and configuration. Use no shutdown where appropriate."
    },

    "Physical Link": {
        "severity": "High",
        "root_cause": "The physical network connection is faulty or disconnected.",
        "explanation": "A damaged cable, connector or switch port can prevent network communication.",
        "fix": "Check the Ethernet cable, connectors, switch port and interface error counters."
    },

    "Speed/Duplex": {
        "severity": "Medium",
        "root_cause": "The connected interfaces have incompatible speed or duplex settings.",
        "explanation": "Speed or duplex mismatches can cause poor performance and packet errors.",
        "fix": "Configure matching speed and duplex settings on both connected interfaces."
    },

    "Wireless": {
        "severity": "Medium",
        "root_cause": "Wireless security or radio configuration is causing connectivity problems.",
        "explanation": "Incorrect security settings or radio interference can affect wireless connectivity.",
        "fix": "Verify wireless security settings and check channel utilization and interference."
    },

    "Subnet Mask": {
        "severity": "High",
        "root_cause": "The configured subnet mask does not match the expected network.",
        "explanation": "An incorrect subnet mask can place hosts in the wrong network.",
        "fix": "Configure the correct subnet mask for the affected interface or host."
    }
}


# =========================================================
# DEFAULT KNOWLEDGE
# =========================================================

DEFAULT_KNOWLEDGE = {
    "severity": "Medium",
    "root_cause": "A network configuration or connectivity problem was detected.",
    "explanation": "The checker identified network evidence that requires investigation.",
    "fix": "Review the network configuration and verify the affected device and connectivity."
}


# =========================================================
# CONFIDENCE
# =========================================================

def calculate_confidence(finding):

    rule = str(
        finding.get("rule", "")
    ).strip()

    message = str(
        finding.get("message", "")
    ).strip()

    if rule and message:
        return 95

    if rule:
        return 85

    return 70


# =========================================================
# BUILD EVIDENCE
# =========================================================

def build_evidence(finding):

    rule = str(
        finding.get("rule", "")
    ).strip()

    message = str(
        finding.get("message", "")
    ).strip()

    return f"{rule}: {message}"


# =========================================================
# BUILD DIAGNOSIS
# =========================================================

def build_diagnosis(case):

    findings = case.get(
        "findings",
        []
    )

    diagnoses = []

    for finding in findings:

        rule = str(
            finding.get(
                "rule",
                "Unknown"
            )
        ).strip()

        message = str(
            finding.get(
                "message",
                "Network fault detected."
            )
        ).strip()

        knowledge = FAULT_KNOWLEDGE.get(
            rule,
            DEFAULT_KNOWLEDGE
        )

        confidence = calculate_confidence(
            finding
        )

        evidence = build_evidence(
            finding
        )

        diagnoses.append({

            "category": rule,

            "severity":
                knowledge["severity"],

            "problem":
                message,

            "root_cause":
                knowledge["root_cause"],

            "explanation":
                knowledge["explanation"],

            "recommended_fix":
                knowledge["fix"],

            "evidence":
                evidence,

            "confidence":
                f"{confidence}%"
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
            "Run checker/rule_checker.py first."
        )

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

        print(
            "ERROR: Unable to read checker_results.json."
        )

        return []


# =========================================================
# DISPLAY DIAGNOSIS
# =========================================================

def display_diagnosis(case):

    case_id = case.get(
        "case_id",
        "UNKNOWN"
    )

    diagnoses = build_diagnosis(
        case
    )

    print(
        "\n=========================================="
    )

    print(
        f"NETSAGE AI DIAGNOSIS V2 - {case_id}"
    )

    print(
        "=========================================="
    )

    if not diagnoses:

        print(
            "\nOK: No deterministic fault detected."
        )

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
            f"Root Cause      : "
            f"{diagnosis['root_cause']}"
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
            f"Evidence        : "
            f"{diagnosis['evidence']}"
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
        "\nNetSage AI Diagnosis Engine V2"
    )

    print(
        "================================"
    )

    case_id = input(
        "\nEnter Case ID "
        "(example CASE002): "
    ).strip().upper()

    selected_case = None

    for case in results:

        current_id = str(
            case.get(
                "case_id",
                ""
            )
        ).upper()

        if current_id == case_id:

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