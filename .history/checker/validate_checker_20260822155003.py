import csv
import json
from pathlib import Path


# =========================================================
# NETSAGE AI - CHECKER VALIDATOR V4.2
# =========================================================


# ---------------------------------------------------------
# File Configuration
# ---------------------------------------------------------

CSV_FILE = Path("data/cases_v3_final_1.csv")
RESULT_FILE = Path("checker_results.json")


# ---------------------------------------------------------
# Helper Function
# ---------------------------------------------------------

def normalize(text):
    """
    Normalize text so that different naming styles
    can be compared consistently.
    """

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
    """
    Convert the dataset's expected fault into
    a broad category.
    """

    text = normalize(expected_fault)
    words = set(text.split())

    # -----------------------------------------------------
    # Duplicate IP
    # -----------------------------------------------------

    if (
        "duplicate ip" in text
        or ("duplicate" in words and "ip" in words)
    ):
        return "duplicate"

    # -----------------------------------------------------
    # Subnet / Mask
    # -----------------------------------------------------

    if (
        "subnet" in words
        or "mask" in words
    ):
        return "subnet"

    # -----------------------------------------------------
    # Gateway
    # -----------------------------------------------------

    if "gateway" in words:
        return "gateway"

    # -----------------------------------------------------
    # Interface / Physical Link
    # -----------------------------------------------------

    if (
        "interface" in words
        or "physical" in words
        or "link" in words
        or "cabling" in words
    ):
        return "interface"

    # -----------------------------------------------------
    # VLAN / Trunk / 802.1Q
    # -----------------------------------------------------

    if (
        "vlan" in words
        or "trunk" in words
        or "802.1q" in text
        or "native vlan" in text
    ):
        return "vlan"

    # -----------------------------------------------------
    # Routing / OSPF / Next Hop
    # -----------------------------------------------------

    if (
        "route" in words
        or "routing" in words
        or "ospf" in words
        or "next hop" in text
    ):
        return "routing"

    # -----------------------------------------------------
    # NAT
    # -----------------------------------------------------

    if (
        "nat" in words
        or "static nat" in text
    ):
        return "nat"

    # -----------------------------------------------------
    # ACL
    # -----------------------------------------------------

    if (
        "acl" in words
        or "access control" in text
    ):
        return "acl"

    # -----------------------------------------------------
    # DHCP
    # -----------------------------------------------------

    if "dhcp" in words:
        return "dhcp"

    # -----------------------------------------------------
    # DNS
    # -----------------------------------------------------

    if "dns" in words:
        return "dns"

    # -----------------------------------------------------
    # Wireless
    # -----------------------------------------------------

    if (
        "wireless" in words
        or "wifi" in words
        or "wi fi" in text
        or "wi-fi" in text
    ):
        return "wireless"

    # -----------------------------------------------------
    # Speed / Duplex
    # -----------------------------------------------------

    if (
        "speed" in words
        or "duplex" in words
        or "speed/duplex" in text
    ):
        return "speed_duplex"

    # -----------------------------------------------------
    # Other
    # -----------------------------------------------------

    return "other"


# =========================================================
# RULE CLASSIFICATION
# =========================================================

def classify_rule(rule_name):
    """
    Convert the rule checker's rule name into
    the same broad category system.
    """

    rule = normalize(rule_name)
    words = set(rule.split())

    # -----------------------------------------------------
    # Duplicate IP
    # -----------------------------------------------------

    if (
        "duplicate" in words
        and "ip" in words
    ):
        return "duplicate"

    # -----------------------------------------------------
    # Subnet / Mask
    # -----------------------------------------------------

    if (
        "subnet" in words
        or "mask" in words
    ):
        return "subnet"

    # -----------------------------------------------------
    # Gateway
    # -----------------------------------------------------

    if "gateway" in words:
        return "gateway"

    # -----------------------------------------------------
    # Interface / Physical Link
    # -----------------------------------------------------

    if (
        "interface" in words
        or "physical" in words
        or "link" in words
        or "cabling" in words
    ):
        return "interface"

    # -----------------------------------------------------
    # VLAN / Trunk / Native VLAN / 802.1Q
    # -----------------------------------------------------

    if (
        "vlan" in words
        or "trunk" in words
        or "native" in words
        or "802.1q" in rule
    ):
        return "vlan"

    # -----------------------------------------------------
    # Routing
    # -----------------------------------------------------

    if (
        "routing" in words
        or "route" in words
        or "ospf" in words
        or "next hop" in rule
    ):
        return "routing"

    # -----------------------------------------------------
    # NAT
    # -----------------------------------------------------

    if "nat" in words:
        return "nat"

    # -----------------------------------------------------
    # ACL
    # -----------------------------------------------------

    if (
        "acl" in words
        or "access" in words
    ):
        return "acl"

    # -----------------------------------------------------
    # DHCP
    # -----------------------------------------------------

    if "dhcp" in words:
        return "dhcp"

    # -----------------------------------------------------
    # DNS
    # -----------------------------------------------------

    if "dns" in words:
        return "dns"

    # -----------------------------------------------------
    # Wireless
    # -----------------------------------------------------

    if (
        "wireless" in words
        or "wifi" in words
        or "wi fi" in rule
    ):
        return "wireless"

    # -----------------------------------------------------
    # Speed / Duplex
    # -----------------------------------------------------

    if (
        "speed" in words
        or "duplex" in words
    ):
        return "speed_duplex"

    # -----------------------------------------------------
    # Other
    # -----------------------------------------------------

    return "other"


# =========================================================
# MAIN VALIDATION
# =========================================================

def main():

    print("\n==========================================")
    print("       NETSAGE AI CHECKER VALIDATOR V4.2")
    print("==========================================\n")

    # -----------------------------------------------------
    # Check CSV
    # -----------------------------------------------------

    if not CSV_FILE.exists():

        print("ERROR: CSV file not found.")
        print(f"Expected: {CSV_FILE}")

        return

    # -----------------------------------------------------
    # Check JSON
    # -----------------------------------------------------

    if not RESULT_FILE.exists():

        print("ERROR: checker_results.json not found.")
        print("Run rule_checker.py first.")

        return

    # =====================================================
    # LOAD EXPECTED FAULTS
    # =====================================================

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

            expected_cases[case_id] = {
                "expected_fault": row.get(
                    "expected_fault",
                    ""
                )
            }

    # =====================================================
    # LOAD CHECKER RESULTS
    # =====================================================

    with open(
        RESULT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        checker_results = json.load(file)

    # =====================================================
    # METRICS
    # =====================================================

    true_positive = 0
    false_positive = 0
    false_negative = 0
    correct_no_fault = 0

    print("------------------------------------------")

    # =====================================================
    # VALIDATE EACH CASE
    # =====================================================

    for case in checker_results:

        case_id = case.get("case_id")

        # -------------------------------------------------
        # Expected fault
        # -------------------------------------------------

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

        # -------------------------------------------------
        # Detected categories
        # -------------------------------------------------

        detected_categories = []

        for finding in case.get(
            "findings",
            []
        ):

            rule_name = finding.get(
                "rule",
                ""
            )

            category = classify_rule(
                rule_name
            )

            detected_categories.append(
                category
            )

        # -------------------------------------------------
        # Expected fault exists
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

    # =====================================================
    # CALCULATE METRICS
    # =====================================================

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

    accuracy = 0.0

    if total > 0:

        accuracy = (
            correct_predictions
            / total
        ) * 100

    # =====================================================
    # SUMMARY
    # =====================================================

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
# PROGRAM ENTRY
# =========================================================

if __name__ == "__main__":
    main()