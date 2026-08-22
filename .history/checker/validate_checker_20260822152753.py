import csv
import json
from pathlib import Path


CSV_FILE = Path("data/cases_v3_final_1.csv")
RESULT_FILE = Path("checker_results.json")


def normalize(text):
    """Normalize text for simple comparison."""

    if not text:
        return ""

    return (
        str(text)
        .lower()
        .replace("-", " ")
        .replace("_", " ")
        .strip()
    )


def classify_expected_fault(expected_fault):
    """
    Convert the dataset's expected fault into a broad
    category that can be compared with rule findings.
    """

    text = normalize(expected_fault)

    if "duplicate ip" in text:
        return "duplicate"

    if "subnet" in text or "mask" in text:
        return "subnet"

    if "gateway" in text:
        return "gateway"

    if "interface" in text or "link" in text:
        return "interface"

    if "vlan" in text:
        return "vlan"

    if "route" in text or "routing" in text or "ospf" in text:
        return "routing"

    if "nat" in text:
        return "nat"

    if "acl" in text or "access control" in text:
        return "acl"

    if "dhcp" in text:
        return "dhcp"

    if "dns" in text:
        return "dns"

    if "speed" in text or "duplex" in text:
        return "speed_duplex"

    return "other"


def classify_rule(rule_name):
    """Convert checker rule name into a category."""

    rule = normalize(rule_name)

    if "duplicate ip" in rule:
        return "duplicate"

    if "subnet" in rule:
        return "subnet"

    if "gateway" in rule:
        return "gateway"

    if "interface" in rule:
        return "interface"

    if "vlan" in rule:
        return "vlan"

    if "routing" in rule or "ospf" in rule:
        return "routing"

    if "nat" in rule:
        return "nat"

    if "acl" in rule:
        return "acl"

    if "dhcp" in rule:
        return "dhcp"

    if "dns" in rule:
        return "dns"

    if "speed" in rule or "duplex" in rule:
        return "speed_duplex"

    return "other"


def main():

    print("\n==========================================")
    print("       NETSAGE AI CHECKER VALIDATOR")
    print("==========================================\n")

    if not CSV_FILE.exists():
        print("ERROR: CSV file not found.")
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

            expected_cases[case_id] = {
                "expected_fault": row.get(
                    "expected_fault",
                    ""
                )
            }

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
    # Validation
    # -----------------------------------------------------

    true_positive = 0
    false_positive = 0
    false_negative = 0
    correct_no_fault = 0

    print("------------------------------------------")

    for case in checker_results:

        case_id = case["case_id"]

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
            classify_rule(finding["rule"])
            for finding in case.get("findings", [])
        ]

        # -------------------------------------------------
        # No expected fault
        # -------------------------------------------------

        if not expected_text.strip():

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

            continue

        # -------------------------------------------------
        # Expected fault exists
        # -------------------------------------------------

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

    # -----------------------------------------------------
    # Metrics
    # -----------------------------------------------------

    total = (
        true_positive
        + false_positive
        + false_negative
        + correct_no_fault
    )

    print("\n==========================================")
    print("VALIDATION SUMMARY")
    print("==========================================")

    print(f"Total cases       : {total}")
    print(f"True positives    : {true_positive}")
    print(f"False positives   : {false_positive}")
    print(f"False negatives   : {false_negative}")
    print(f"Correct no fault  : {correct_no_fault}")

    if total > 0:

        accuracy = (
            true_positive + correct_no_fault
        ) / total * 100

        print(
            f"Detection accuracy: "
            f"{accuracy:.2f}%"
        )

    print("\nValidation completed.")


if __name__ == "__main__":
    main()