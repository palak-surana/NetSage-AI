import csv
import json
from pathlib import Path


# =========================================================
# NETSAGE AI - CHECKER VALIDATOR V4.3
# =========================================================

CSV_FILE = Path("data/cases_v3_final_1.csv")
RESULT_FILE = Path("checker_results.json")


# =========================================================
# NORMALIZE
# =========================================================

def normalize(text):
    if not text:
        return ""

    return (
        str(text)
        .lower()
        .replace("-", " ")
        .replace("_", " ")
        .strip()
    )


# =========================================================
# EXPECTED FAULT CLASSIFICATION
# =========================================================

def classify_expected_fault(expected_fault):

    text = normalize(expected_fault)

    # -----------------------------------------------------
    # IMPORTANT:
    # Specific categories MUST come before generic words
    # such as "interface", "subnet", etc.
    # -----------------------------------------------------

    # NAT
    if (
        "nat" in text
        or "static nat" in text
        or "nat mapping" in text
        or "nat not configured" in text
    ):
        return "nat"

    # ACL
    if (
        "acl" in text
        or "access control" in text
        or "guest isolation" in text
    ):
        return "acl"

    # Wireless
    if (
        "wireless" in text
        or "wifi" in text
        or "wi-fi" in text
        or "security key" in text
        or "channel interference" in text
    ):
        return "wireless"

    # Speed / Duplex
    if (
        "speed" in text
        or "duplex" in text
        or "speed/duplex" in text
    ):
        return "speed_duplex"

    # Duplicate IP
    if (
        "duplicate ip" in text
        or "ip conflict" in text
    ):
        return "duplicate"

    # VLAN
    if (
        "vlan" in text
        or "802.1q" in text
        or "trunk" in text
        or "native vlan" in text
    ):
        return "vlan"

    # Gateway
    if "gateway" in text:
        return "gateway"

    # DHCP
    if "dhcp" in text:
        return "dhcp"

    # DNS
    if "dns" in text:
        return "dns"

    # Routing
    if (
        "routing" in text
        or "route" in text
        or "ospf" in text
        or "next hop" in text
    ):
        return "routing"

    # Subnet
    if (
        "subnet" in text
        or "subnet mask" in text
    ):
        return "subnet"

    # Interface / Physical
    if (
        "interface" in text
        or "physical" in text
        or "cabling" in text
        or "link" in text
    ):
        return "interface"

    return "other"


# =========================================================
# CHECKER RULE CLASSIFICATION
# =========================================================

def classify_rule(rule_name):

    rule = normalize(rule_name)

    # -----------------------------------------------------
    # Specific categories first
    # -----------------------------------------------------

    # NAT
    if "nat" in rule:
        return "nat"

    # ACL
    if (
        "acl" in rule
        or "access control" in rule
    ):
        return "acl"

    # Wireless
    if (
        "wireless" in rule
        or "wifi" in rule
        or "wi-fi" in rule
    ):
        return "wireless"

    # Speed / Duplex
    if (
        "speed" in rule
        or "duplex" in rule
    ):
        return "speed_duplex"

    # Duplicate IP
    if (
        "duplicate ip" in rule
        or "ip conflict" in rule
    ):
        return "duplicate"

    # VLAN
    #
    # IMPORTANT:
    # "VLAN/Trunk" is NOT split by spaces.
    # Therefore substring checking is required.
    #
    if (
        "vlan" in rule
        or "trunk" in rule
        or "802.1q" in rule
        or "native vlan" in rule
    ):
        return "vlan"

    # Gateway
    if "gateway" in rule:
        return "gateway"

    # DHCP
    if "dhcp" in rule:
        return "dhcp"

    # DNS
    if "dns" in rule:
        return "dns"

    # Routing
    if (
        "routing" in rule
        or "route" in rule
        or "ospf" in rule
        or "next hop" in rule
    ):
        return "routing"

    # Subnet
    if (
        "subnet" in rule
        or "mask" in rule
    ):
        return "subnet"

    # Interface / Physical Link
    if (
        "interface" in rule
        or "physical" in rule
        or "cabling" in rule
        or "link" in rule
    ):
        return "interface"

    return "other"


# =========================================================
# MAIN
# =========================================================

def main():

    print("\n==========================================")
    print("       NETSAGE AI CHECKER VALIDATOR V4.3")
    print("==========================================\n")

    # -----------------------------------------------------
    # File checks
    # -----------------------------------------------------

    if not CSV_FILE.exists():

        print("ERROR: CSV file not found.")
        print(f"Expected: {CSV_FILE}")
        return

    if not RESULT_FILE.exists():

        print("ERROR: checker_results.json not found.")
        print("Run rule_checker.py first.")
        return

    # -----------------------------------------------------
    # Load expected faults
    # -----------------------------------------------------

    expected_cases = {}

    with open(
        CSV_FILE,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            case_id = row.get("case_id")

            if not case_id:
                continue

            expected_cases[case_id] = row.get(
                "expected_fault",
                ""
            )

    # -----------------------------------------------------
    # Load checker results
    # -----------------------------------------------------

    with open(
        RESULT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        checker_results = json.load(file)

    # -----------------------------------------------------
    # Metrics
    # -----------------------------------------------------

    true_positive = 0
    false_positive = 0
    false_negative = 0
    correct_no_fault = 0

    print("------------------------------------------")

    # -----------------------------------------------------
    # Validate
    # -----------------------------------------------------

    for case in checker_results:

        case_id = case.get("case_id")

        expected_text = expected_cases.get(
            case_id,
            ""
        )

        expected_category = classify_expected_fault(
            expected_text
        )

        detected_categories = []

        for finding in case.get("findings", []):

            rule_name = finding.get(
                "rule",
                ""
            )

            detected_categories.append(
                classify_rule(rule_name)
            )

        # -------------------------------------------------
        # Expected fault
        # -------------------------------------------------

        if expected_text.strip():

            if expected_category in detected_categories:

                true_positive += 1

                print(
                    f"✅ {case_id}: "
                    f"Detected {expected_category}"
                )

            else:

                false_negative += 1

                print(
                    f"❌ {case_id}: "
                    f"Missed {expected_category}"
                )

        # -------------------------------------------------
        # No expected fault
        # -------------------------------------------------

        else:

            if detected_categories:

                false_positive += 1

                print(
                    f"❌ {case_id}: "
                    f"False Positive"
                )

            else:

                correct_no_fault += 1

                print(
                    f"✅ {case_id}: "
                    f"Correct - no fault"
                )

    # -----------------------------------------------------
    # Metrics
    # -----------------------------------------------------

    total = (
        true_positive
        + false_positive
        + false_negative
        + correct_no_fault
    )

    correct = (
        true_positive
        + correct_no_fault
    )

    accuracy = 0.0

    if total > 0:
        accuracy = (
            correct / total
        ) * 100

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    print("\n==========================================")
    print("VALIDATION SUMMARY")
    print("==========================================")

    print(
        f"Total cases       : {total}"
    )

    print(
        f"True positives    : {true_positive}"
    )

    print(
        f"False positives   : {false_positive}"
    )

    print(
        f"False negatives   : {false_negative}"
    )

    print(
        f"Correct no fault  : {correct_no_fault}"
    )

    print(
        f"Detection accuracy: {accuracy:.2f}%"
    )

    print("\nValidation completed.")


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()