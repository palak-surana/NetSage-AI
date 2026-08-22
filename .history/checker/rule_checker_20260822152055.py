import csv
import ipaddress
import re
import sys

# Make Windows PowerShell handle UTF-8 symbols such as ✅ and ❌
sys.stdout.reconfigure(encoding="utf-8")


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
    """
    Detect duplicate IP conflicts only when the evidence
    explicitly indicates an IP conflict.
    """

    text_lower = text.lower()

    conflict_keywords = [
        "duplicate ip",
        "same ip",
        "ip conflict",
        "address conflict",
        "two pcs have the same ip",
        "two hosts have the same ip",
        "two devices have the same ip"
    ]

    conflict_detected = any(
        keyword in text_lower
        for keyword in conflict_keywords
    )

    if not conflict_detected:

        return {
            "rule": "Duplicate IP",
            "status": "PASS",
            "message": "No confirmed duplicate IP conflict detected."
        }

    ips = extract_ips(text)

    duplicates = []

    for ip in set(ips):

        if ips.count(ip) > 1:
            duplicates.append(ip)

    if duplicates:

        return {
            "rule": "Duplicate IP",
            "status": "FAIL",
            "message": (
                f"Confirmed duplicate IP conflict: "
                f"{', '.join(duplicates)}"
            )
        }

    return {
        "rule": "Duplicate IP",
        "status": "FAIL",
        "message": "IP conflict indicated by network evidence."
    }


# ---------------------------------------------------------
# Rule 2: Invalid IP Detection
# ---------------------------------------------------------

def check_invalid_ips(text):
    """Detect invalid IPv4 addresses."""

    ips = extract_ips(text)

    invalid = []

    for ip in ips:

        if not valid_ip(ip):
            invalid.append(ip)

    if invalid:

        return {
            "rule": "Invalid IP",
            "status": "FAIL",
            "message": (
                f"Invalid IP address detected: "
                f"{', '.join(invalid)}"
            )
        }

    return {
        "rule": "Invalid IP",
        "status": "PASS",
        "message": "All detected IP addresses are valid."
    }


# ---------------------------------------------------------
# Rule 3: Subnet Mask Detection
# ---------------------------------------------------------

def check_subnet_mask(text):
    """
    Detect explicitly reported subnet-mask problems.
    """

    text_lower = text.lower()

    keywords = [
        "wrong subnet mask",
        "incorrect subnet mask",
        "invalid subnet mask",
        "mask mismatch",
        "subnet mask mismatch",
        "wrong mask",
        "incorrect mask",
        "mask is incorrect"
    ]

    for keyword in keywords:

        if keyword in text_lower:

            return {
                "rule": "Subnet Mask",
                "status": "FAIL",
                "message": (
                    f"Possible subnet mask problem detected: "
                    f"'{keyword}'"
                )
            }

    return {
        "rule": "Subnet Mask",
        "status": "PASS",
        "message": "No explicit subnet-mask problem detected."
    }


# ---------------------------------------------------------
# Rule 4: Interface Down Detection
# ---------------------------------------------------------

def check_interface_down(text):
    """Detect interfaces that are down."""

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
                "message": (
                    f"Possible interface problem detected: "
                    f"'{keyword}'"
                )
            }

    return {
        "rule": "Interface Status",
        "status": "PASS",
        "message": "No interface-down condition detected."
    }


# ---------------------------------------------------------
# Rule 5: Missing VLAN Detection
# ---------------------------------------------------------

def check_missing_vlan(text):
    """Detect possible missing or incorrect VLAN configuration."""

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
                "message": (
                    "Possible missing or incorrect VLAN "
                    "configuration."
                )
            }

    return {
        "rule": "VLAN Configuration",
        "status": "PASS",
        "message": "No explicit missing VLAN condition detected."
    }


# ---------------------------------------------------------
# Rule 6: Missing Route Detection
# ---------------------------------------------------------

def check_missing_route(text):
    """Detect possible missing or incorrect routing."""

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
                "message": (
                    "Possible missing or incorrect route detected."
                )
            }

    return {
        "rule": "Routing",
        "status": "PASS",
        "message": "No explicit missing-route condition detected."
    }


# ---------------------------------------------------------
# Rule 7: Gateway Mismatch Detection
# ---------------------------------------------------------

def check_gateway(text):
    """Detect possible default gateway mismatch."""

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
                "message": (
                    "Possible default gateway mismatch detected."
                )
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

    IMPORTANT:
    We use only the symptom, topology note, and show output.
    We do NOT use expected_fault or evidence_expected because
    those contain the answer and would cause data leakage.
    """

    combined_text = " ".join([
        str(case.get("symptom", "")),
        str(case.get("topology_note", "")),
        str(case.get("show_output", ""))
    ])

    results = []

    # Rule 1
    results.append(
        check_duplicate_ips(combined_text)
    )

    # Rule 2
    results.append(
        check_invalid_ips(combined_text)
    )

    # Rule 3
    results.append(
        check_subnet_mask(combined_text)
    )

    # Rule 4
    results.append(
        check_interface_down(combined_text)
    )

    # Rule 5
    results.append(
        check_missing_vlan(combined_text)
    )

    # Rule 6
    results.append(
        check_missing_route(combined_text)
    )

    # Rule 7
    results.append(
        check_gateway(combined_text)
    )

    return results


# ---------------------------------------------------------
# Process CSV
# ---------------------------------------------------------

def process_csv(filename):

    print("\n======================================")
    print("       NETSAGE AI RULE CHECKER")
    print("======================================\n")

    try:

        with open(
            filename,
            "r",
            encoding="utf-8-sig",
            newline=""
        ) as file:

            reader = csv.DictReader(file)

            total_cases = 0
            failed_rules = 0

            for case in reader:

                total_cases += 1

                case_id = case.get(
                    "case_id",
                    f"CASE-{total_cases}"
                )

                print("--------------------------------------")
                print(f"Case: {case_id}")

                results = run_rules(case)

                for result in results:

                    if result["status"] == "FAIL":
                        symbol = "❌"
                        failed_rules += 1

                    else:
                        symbol = "✅"

                    print(
                        f"{symbol} "
                        f"{result['rule']}: "
                        f"{result['message']}"
                    )

            print("\n======================================")
            print("SUMMARY")
            print("======================================")

            print(
                f"Total cases checked : "
                f"{total_cases}"
            )

            print(
                f"Rule failures found : "
                f"{failed_rules}"
            )

            print("\nRule checker completed.")

    except FileNotFoundError:

        print("\nERROR: CSV file not found.")
        print(f"Expected file: {filename}")

    except Exception as error:

        print("\nERROR while running Rule Checker:")
        print(error)


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    csv_file = "data/cases_v3_final_1.csv"

    process_csv(csv_file)