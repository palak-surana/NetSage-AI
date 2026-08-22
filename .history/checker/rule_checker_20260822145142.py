import csv
import ipaddress
import re


# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------

def extract_ips(text):
    """Extract IPv4 addresses from text."""
    if not text:
        return []

    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(pattern, text)


def valid_ip(ip):
    """Check whether an IP address is valid."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------
# Rule 1: Duplicate IP Detection
# ---------------------------------------------------------

def check_duplicate_ips(text):
    ips = extract_ips(text)

    duplicates = []

    for ip in set(ips):
        if ips.count(ip) > 1:
            duplicates.append(ip)

    if duplicates:
        return {
            "rule": "Duplicate IP",
            "status": "FAIL",
            "message": f"Duplicate IP address detected: {', '.join(duplicates)}"
        }

    return {
        "rule": "Duplicate IP",
        "status": "PASS",
        "message": "No duplicate IP detected."
    }


# ---------------------------------------------------------
# Rule 2: Invalid IP Detection
# ---------------------------------------------------------

def check_invalid_ips(text):
    ips = extract_ips(text)

    invalid = []

    for ip in ips:
        if not valid_ip(ip):
            invalid.append(ip)

    if invalid:
        return {
            "rule": "Invalid IP",
            "status": "FAIL",
            "message": f"Invalid IP address detected: {', '.join(invalid)}"
        }

    return {
        "rule": "Invalid IP",
        "status": "PASS",
        "message": "All detected IP addresses are valid."
    }


# ---------------------------------------------------------
# Rule 3: Interface Down Detection
# ---------------------------------------------------------

def check_interface_down(text):
    text_lower = text.lower()

    keywords = [
        "administratively down",
        "interface down",
        "line protocol is down",
        "status down",
        "protocol down"
    ]

    for keyword in keywords:
        if keyword in text_lower:
            return {
                "rule": "Interface Status",
                "status": "FAIL",
                "message": f"Possible interface problem detected: '{keyword}'"
            }

    return {
        "rule": "Interface Status",
        "status": "PASS",
        "message": "No interface-down condition detected."
    }


# ---------------------------------------------------------
# Rule 4: Missing VLAN Detection
# ---------------------------------------------------------

def check_missing_vlan(text):
    text_lower = text.lower()

    keywords = [
        "vlan does not exist",
        "vlan missing",
        "unknown vlan",
        "not in vlan",
        "vlan not found"
    ]

    for keyword in keywords:
        if keyword in text_lower:
            return {
                "rule": "VLAN Configuration",
                "status": "FAIL",
                "message": "Possible missing or incorrect VLAN configuration."
            }

    return {
        "rule": "VLAN Configuration",
        "status": "PASS",
        "message": "No explicit missing VLAN condition detected."
    }


# ---------------------------------------------------------
# Rule 5: Missing Route Detection
# ---------------------------------------------------------

def check_missing_route(text):
    text_lower = text.lower()

    keywords = [
        "network not in routing table",
        "route missing",
        "no route",
        "destination unreachable",
        "network unreachable",
        "routing table does not contain"
    ]

    for keyword in keywords:
        if keyword in text_lower:
            return {
                "rule": "Routing",
                "status": "FAIL",
                "message": "Possible missing or incorrect route detected."
            }

    return {
        "rule": "Routing",
        "status": "PASS",
        "message": "No explicit missing-route condition detected."
    }


# ---------------------------------------------------------
# Rule 6: Gateway Mismatch Detection
# ---------------------------------------------------------

def check_gateway(text):
    text_lower = text.lower()

    keywords = [
        "wrong gateway",
        "incorrect gateway",
        "gateway mismatch",
        "default gateway incorrect",
        "default gateway wrong"
    ]

    for keyword in keywords:
        if keyword in text_lower:
            return {
                "rule": "Gateway",
                "status": "FAIL",
                "message": "Possible default gateway mismatch detected."
            }

    return {
        "rule": "Gateway",
        "status": "PASS",
        "message": "No explicit gateway mismatch detected."
    }


# ---------------------------------------------------------
# Run All Rules
# ---------------------------------------------------------

def run_rules(case):
    """
    Run deterministic checks against one troubleshooting case.
    """

    combined_text = " ".join([
        str(case.get("symptom", "")),
        str(case.get("topology_note", "")),
        str(case.get("show_outputs", "")),
        str(case.get("expected_fault", "")),
        str(case.get("evidence_expected", ""))
    ])

    results = []

    results.append(check_duplicate_ips(combined_text))
    results.append(check_invalid_ips(combined_text))
    results.append(check_interface_down(combined_text))
    results.append(check_missing_vlan(combined_text))
    results.append(check_missing_route(combined_text))
    results.append(check_gateway(combined_text))

    return results


# ---------------------------------------------------------
# Process CSV
# ---------------------------------------------------------

def process_csv(filename):

    print("\n======================================")
    print("       NETSAGE AI RULE CHECKER")
    print("======================================\n")

    with open(filename, "r", encoding="utf-8-sig") as file:

        reader = csv.DictReader(file)

        total_cases = 0
        failed_rules = 0

        for case in reader:

            total_cases += 1

            case_id = case.get("case_id", f"CASE-{total_cases}")

            print("--------------------------------------")
            print(f"Case: {case_id}")

            results = run_rules(case)

            for result in results:

                symbol = "❌" if result["status"] == "FAIL" else "✅"

                print(
                    f"{symbol} {result['rule']}: "
                    f"{result['message']}"
                )

                if result["status"] == "FAIL":
                    failed_rules += 1

    print("\n======================================")
    print("SUMMARY")
    print("======================================")

    print(f"Total cases checked : {total_cases}")
    print(f"Rule failures found : {failed_rules}")

    print("\nRule checker completed.")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    csv_file = "data/cases_v3_final_1.csv""

    process_csv(csv_file)