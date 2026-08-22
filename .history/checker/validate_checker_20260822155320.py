import csv
import json
from pathlib import Path


# =========================================================
# NETSAGE AI - CHECKER VALIDATOR V5
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
# EXPECTED FAULT
# =========================================================

def classify_expected_fault(expected_fault):

    text = normalize(expected_fault)

    # Most specific categories FIRST.

    if "duplicate ip" in text:
        return "duplicate"

    if "speed/duplex" in text:
        return "speed_duplex"

    if "speed" in text or "duplex" in text:
        return "speed_duplex"

    if "wireless" in text:
        return "wireless"

    if "security key" in text:
        return "wireless"

    if "channel interference" in text:
        return "wireless"

    if "acl" in text:
        return "acl"

    if "guest isolation" in text:
        return "acl"

    if "nat" in text:
        return "nat"

    if "dns" in text:
        return "dns"

    if "dhcp" in text:
        return "dhcp"

    if "gateway" in text:
        return "gateway"

    if (
        "vlan" in text
        or "trunk" in text
        or "802.1q" in text
    ):
        return "vlan"

    if (
        "routing" in text
        or "route" in text
        or "ospf" in text
        or "next hop" in text
    ):
        return "routing"

    if (
        "subnet" in text
        or "subnet mask" in text
    ):
        return "subnet"

    if (
        "interface" in text
        or "physical" in text
        or "cabling" in text
        or "link" in text
    ):
        return "interface"

    return "other"


# =========================================================
# DETECTED RULE
# =========================================================

def classify_rule(rule_name):

    rule = normalize(rule_name)

    # Specific categories FIRST.

    if "duplicate ip" in rule:
        return "duplicate"

    if (
        "speed" in rule
        or "duplex" in rule
    ):
        return "speed_duplex"

    if "wireless" in rule:
        return "wireless"

    if "acl" in rule:
        return "acl"

    if "nat" in rule:
        return "nat"

    if "dns" in rule:
        return "dns"

    if "dhcp" in rule:
        return "dhcp"

    if "gateway" in rule:
        return "gateway"

    if (
        "vlan" in rule
        or "trunk" in rule
        or "802.1q" in rule
        or "native vlan" in rule
    ):
        return "vlan"

    if (
        "routing" in rule
        or "route" in rule
        or "ospf" in rule
    ):
        return "routing"

    if "subnet" in rule:
        return "subnet"

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
    print("       NETSAGE AI CHECKER VALIDATOR V5")
    print("==========================================\n")

    if not CSV_FILE.exists():

        print("ERROR: CSV file not found.")
        print(f"Expected: {CSV_FILE}")
        return

    if not RESULT_FILE.exists():

        print("ERROR: checker_results.json not found.")
        print("Run rule_checker.py first.")
        return

    # =====================================================
    # LOAD EXPECTED DATA
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
    # LOAD RESULTS
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
    # VALIDATE
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

        for finding in case.get("findings", []):

            rule = finding.get(
                "rule",
                ""
            )

            detected_categories.append(
                classify_rule(rule)
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
                    f"❌ {case_id}: False Positive"
                )

            else:

                correct_no_fault += 1

                print(
                    f"✅ {case_id}: Correct - no fault"
                )

    # =====================================================
    # METRICS
    # =====================================================

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

    accuracy = 0

    if total > 0:

        accuracy = (
            correct / total
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
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()