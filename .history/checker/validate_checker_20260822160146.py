import csv
import json
from pathlib import Path


# =========================================================
# NETSAGE AI - CHECKER VALIDATOR V6
# =========================================================

CSV_FILE = Path("data/cases_v3_final_1.csv")
RESULT_FILE = Path("checker_results.json")


# =========================================================
# NORMALIZE
# =========================================================

def normalize(text):
    """
    Normalize text for reliable category comparison.
    """

    if not text:
        return ""

    return (
        str(text)
        .lower()
        .replace("-", " ")
        .replace("_", " ")
        .replace("/", " ")
        .strip()
    )


# =========================================================
# EXPECTED FAULT CLASSIFICATION
# =========================================================
def classify_expected_fault(expected_fault):

    text = normalize(expected_fault)

    # =====================================================
    # IMPORTANT:
    # VLAN MUST BE CHECKED BEFORE NAT
    # because "native" contains "nat".
    # =====================================================

    # -----------------------------------------------------
    # Duplicate IP
    # -----------------------------------------------------
    if (
        "duplicate ip" in text
        or "ip conflict" in text
    ):
        return "duplicate"

    # -----------------------------------------------------
    # Speed / Duplex
    # -----------------------------------------------------
    if (
        "speed" in text
        or "duplex" in text
    ):
        return "speed_duplex"

    # -----------------------------------------------------
    # Wireless
    # -----------------------------------------------------
    if (
        "wireless" in text
        or "wifi" in text
        or "security key" in text
        or "channel interference" in text
    ):
        return "wireless"

    # -----------------------------------------------------
    # ACL
    # -----------------------------------------------------
    if (
        "acl" in text
        or "access control" in text
        or "guest isolation" in text
    ):
        return "acl"

    # -----------------------------------------------------
    # VLAN / TRUNK / 802.1Q
    # CHECK THIS BEFORE NAT
    # -----------------------------------------------------
    if (
        "vlan" in text
        or "trunk" in text
        or "802.1q" in text
        or "native" in text
    ):
        return "vlan"

    # -----------------------------------------------------
    # NAT
    # -----------------------------------------------------
    if (
        "static nat" in text
        or "nat mapping" in text
        or "nat not configured" in text
        or "nat outside" in text
        or "nat inside" in text
        or text.startswith("nat ")
        or text == "nat"
    ):
        return "nat"

    # -----------------------------------------------------
    # DNS
    # -----------------------------------------------------
    if "dns" in text:
        return "dns"

    # -----------------------------------------------------
    # DHCP subnet mask
    # -----------------------------------------------------
    if (
        "dhcp" in text
        and (
            "subnet" in text
            or "mask" in text
        )
    ):
        return "subnet"

    # -----------------------------------------------------
    # DHCP
    # -----------------------------------------------------
    if "dhcp" in text:
        return "dhcp"

    # -----------------------------------------------------
    # Gateway
    # -----------------------------------------------------
    if "gateway" in text:
        return "gateway"

    # -----------------------------------------------------
    # Routing
    # -----------------------------------------------------
    if (
        "routing" in text
        or "route" in text
        or "ospf" in text
        or "next hop" in text
    ):
        return "routing"

    # -----------------------------------------------------
    # Subnet
    # -----------------------------------------------------
    if (
        "subnet" in text
        or "subnet mask" in text
    ):
        return "subnet"

    # -----------------------------------------------------
    # Interface
    # -----------------------------------------------------
    if (
        "interface" in text
        or "physical" in text
        or "cabling" in text
        or "link" in text
    ):
        return "interface"

    return "other"



# =========================================================
# DETECTED RULE CLASSIFICATION
# =========================================================

def classify_rule(rule_name):

    rule = normalize(rule_name)

    # -----------------------------------------------------
    # Duplicate IP
    # -----------------------------------------------------
    if (
        "duplicate ip" in rule
        or "ip conflict" in rule
    ):
        return "duplicate"

    # -----------------------------------------------------
    # Speed / Duplex
    # -----------------------------------------------------
    if (
        "speed" in rule
        or "duplex" in rule
    ):
        return "speed_duplex"

    # -----------------------------------------------------
    # Wireless
    # -----------------------------------------------------
    if (
        "wireless" in rule
        or "wifi" in rule
    ):
        return "wireless"

    # -----------------------------------------------------
    # ACL
    # -----------------------------------------------------
    if (
        "acl" in rule
        or "access control" in rule
    ):
        return "acl"

    # -----------------------------------------------------
    # VLAN MUST COME BEFORE NAT
    # -----------------------------------------------------
    if (
        "vlan" in rule
        or "trunk" in rule
        or "802.1q" in rule
        or "native" in rule
    ):
        return "vlan"

    # -----------------------------------------------------
    # NAT
    # -----------------------------------------------------
    if (
        rule == "nat"
        or "nat " in rule
        or "static nat" in rule
    ):
        return "nat"

    # -----------------------------------------------------
    # DNS
    # -----------------------------------------------------
    if "dns" in rule:
        return "dns"

    # -----------------------------------------------------
    # DHCP
    # -----------------------------------------------------
    if "dhcp" in rule:
        return "dhcp"

    # -----------------------------------------------------
    # Gateway
    # -----------------------------------------------------
    if "gateway" in rule:
        return "gateway"

    # -----------------------------------------------------
    # Routing
    # -----------------------------------------------------
    if (
        "routing" in rule
        or "route" in rule
        or "ospf" in rule
        or "next hop" in rule
    ):
        return "routing"

    # -----------------------------------------------------
    # Subnet
    # -----------------------------------------------------
    if (
        "subnet" in rule
        or "mask" in rule
    ):
        return "subnet"

    # -----------------------------------------------------
    # Interface
    # -----------------------------------------------------
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
    print("       NETSAGE AI CHECKER VALIDATOR V6")
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

            if case_id:

                expected_cases[case_id] = row.get(
                    "expected_fault",
                    ""
                )

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
    # VALIDATE EVERY CASE
    # =====================================================

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

        for finding in case.get(
            "findings",
            []
        ):

            rule_name = finding.get(
                "rule",
                ""
            )

            detected_category = classify_rule(
                rule_name
            )

            detected_categories.append(
                detected_category
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