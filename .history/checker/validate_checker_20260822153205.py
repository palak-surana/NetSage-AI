import csv
import json
from pathlib import Path


# ---------------------------------------------------------
# File Configuration
# ---------------------------------------------------------

CSV_FILE = Path("data/cases_v3_final_1.csv")
RESULT_FILE = Path("checker_results.json")


# ---------------------------------------------------------
# Helper: Normalize Text
# ---------------------------------------------------------

def normalize(text):
    """Normalize text for reliable category comparison."""

    if not text:
        return ""

    return (
        str(text)
        .lower()
        .replace("-", " ")
        .replace("_", " ")
        .strip()
    )


# ---------------------------------------------------------
# Classify Expected Fault
# ---------------------------------------------------------

def classify_expected_fault(expected_fault):
    """
    Convert the dataset's expected_fault into a
    broad validation category.

    Specific categories are checked before generic
    words such as 'interface', 'mask', or 'route'.
    """

    text = normalize(expected_fault)

    # -----------------------------------------------------
    # NAT
    # -----------------------------------------------------

    if "nat" in text:
        return "nat"

    # -----------------------------------------------------
    # ACL
    # -----------------------------------------------------

    if "acl" in text or "access control" in text:
        return "acl"

    # -----------------------------------------------------
    # Wireless
    # -----------------------------------------------------

    if (
        "wireless" in text
        or "security key" in text
        or "channel interference" in text
    ):
        return "wireless"

    # -----------------------------------------------------
    # Speed / Duplex
    # -----------------------------------------------------

    if (
        "speed" in text
        or "duplex" in text
    ):
        return "speed_duplex"

    # -----------------------------------------------------
    # VLAN / 802.1Q
    # -----------------------------------------------------

    if (
        "vlan" in text
        or "802.1q" in text
    ):
        return "vlan"

    # -----------------------------------------------------
    # DHCP
    # -----------------------------------------------------

    if "dhcp" in text:
        return "dhcp"

    # -----------------------------------------------------
    # DNS
    # -----------------------------------------------------

    if "dns" in text:
        return "dns"

    # -----------------------------------------------------
    # Duplicate IP
    # -----------------------------------------------------

    if "duplicate ip" in text:
        return "duplicate"

    # -----------------------------------------------------
    # Gateway
    # -----------------------------------------------------

    if "gateway" in text:
        return "gateway"

    # -----------------------------------------------------
    # Subnet Mask
    # -----------------------------------------------------

    if (
        "subnet mask" in text
        or "mask" in text
    ):
        return "subnet"

    # -----------------------------------------------------
    # Routing / OSPF / Next Hop
    # -----------------------------------------------------

    if (
        "route" in text
        or "routing" in text
        or "ospf" in text
        or "next hop" in text
    ):
        return "routing"

    # -----------------------------------------------------
    # Interface / Physical Link
    # -----------------------------------------------------

    if (
        "interface" in text
        or "link" in text
        or "cabling" in text
        or "physical" in text
    ):
        return "interface"

    return "other"


# ---------------------------------------------------------
# Classify Checker Rule
# ---------------------------------------------------------

def classify_rule(rule_name):
    """
    Convert a Rule Checker rule name into the same
    category system used by classify_expected_fault().
    """

    rule = normalize(rule_name)

    # -----------------------------------------------------
    # NAT
    # -----------------------------------------------------

    if "nat" in rule:
        return "nat"

    # -----------------------------------------------------
    # ACL
    # -----------------------------------------------------

    if "acl" in rule:
        return "acl"

    # -----------------------------------------------------
    # Wireless
    # -----------------------------------------------------

    if "wireless" in rule:
        return "wireless"

    # -----------------------------------------------------
    # Speed / Duplex
    # -----------------------------------------------------

    if (
        "speed" in rule
        or "duplex" in rule
    ):
        return "speed_duplex"

    # -----------------------------------------------------
    # VLAN
    # -----------------------------------------------------

    if "vlan" in rule:
        return "vlan"

    # -----------------------------------------------------
    # DHCP
    # -----------------------------------------------------

    if "dhcp" in rule:
        return "dhcp"

    # -----------------------------------------------------
    # DNS
    # -----------------------------------------------------

    if "dns" in rule:
        return "dns"

    # -----------------------------------------------------
    # Duplicate IP
    # -----------------------------------------------------

    if "duplicate ip" in rule:
        return "duplicate"

    # -----------------------------------------------------
    # Gateway
    # -----------------------------------------------------

    if "gateway" in rule:
        return "gateway"

    # -----------------------------------------------------
    # Subnet
    # -----------------------------------------------------

    if "subnet" in rule:
        return "subnet"

    # -----------------------------------------------------
    # Routing
    # -----------------------------------------------------

    if (
        "routing" in rule
        or "ospf" in rule
        or "route" in rule
    ):
        return "routing"

    # -----------------------------------------------------
    # Interface
    # -----------------------------------------------------

    if "interface" in rule:
        return "interface"

    return "other"


# ---------------------------------------------------------
# Main Validation
# ---------------------------------------------------------

def main():

    print("\n==========================================")
    print("       NETSAGE AI CHECKER VALIDATOR")
    print("==========================================\n")

    # -----------------------------------------------------
    # Check files
    # -----------------------------------------------------

    if not CSV_FILE.exists():

        print("ERROR: CSV file not found.")
        print(f"Expected file: {CSV_FILE}")

        return

    if not RESULT_FILE.exists():

        print("ERROR: checker_results.json not found.")
        print("Run rule_checker.py first.")

        return

    # -----------------------------------------------------
    # Load Expected Faults
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

            expected_cases[case_id] = {
                "expected_fault": row.get(
                    "expected_fault",
                    ""
                )
            }

    # -----------------------------------------------------
    # Load Rule Checker Results
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
    # Validate Every Case
    # -----------------------------------------------------

    for case in checker_results:

        case_id = case.get("case_id")

        expected_text = expected_cases.get(
            case_id,
            {}
        ).get(
            "expected_fault",
            ""
        )

        expected_category = classify_expected_fault(
            expected_text
        )

        detected_categories = [
            classify_rule(
                finding.get("rule", "")
            )
            for finding in case.get(
                "findings",
                []
            )
        ]

        # -------------------------------------------------
        # Expected Fault Exists
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
        # No Expected Fault
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
    # Calculate Metrics
    # -----------------------------------------------------

    total = (
        true_positive
        + false_positive
        + false_negative
        + correct_no_fault
    )

    correct_predictions = (
        true_positive
        + correct_no_fault
    )

    accuracy = 0

    if total > 0:

        accuracy = (
            correct_predictions
            / total
        ) * 100

    # -----------------------------------------------------
    # Validation Summary
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


# ---------------------------------------------------------
# Program Entry Point
# ---------------------------------------------------------

if __name__ == "__main__":
    main()