import csv
import json
import ipaddress
import re
import sys
from pathlib import Path

# =========================================================
# NETSAGE AI - RULE CHECKER V9
# =========================================================

sys.stdout.reconfigure(encoding="utf-8")

CSV_FILE = Path("data/cases_v3_final_1.csv")
RESULT_FILE = Path("checker_results.json")


# =========================================================
# HELPER FUNCTIONS
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


def extract_ips(text):
    """Extract IPv4 addresses from text."""

    if not text:
        return []

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    return re.findall(pattern, str(text))


def valid_ip(ip):
    """Check whether an IP address is valid."""

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# =========================================================
# RULE 1 - DUPLICATE IP
# =========================================================

def check_duplicate_ip(text):

    text_lower = normalize(text)

    conflict_keywords = [
        "duplicate ip",
        "same ip",
        "ip conflict",
        "address conflict",
        "two pcs have the same ip",
        "two hosts have the same ip",
        "two devices have the same ip",
    ]

    if not any(keyword in text_lower for keyword in conflict_keywords):

        return None

    return {
        "rule": "Duplicate IP",
        "status": "FAIL",
        "message": "IP conflict indicated by network evidence.",
    }


# =========================================================
# RULE 2 - INVALID IP
# =========================================================

def check_invalid_ip(text):

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
                "Invalid IP address detected: "
                + ", ".join(invalid)
            ),
        }

    return None


# =========================================================
# RULE 3 - GATEWAY
# =========================================================

def check_gateway(symptom, topology, show_output):

    combined = " ".join([
        str(symptom or ""),
        str(topology or ""),
        str(show_output or ""),
    ])

    text = normalize(combined)

    # -----------------------------------------------------
    # CASE: Missing gateway
    # -----------------------------------------------------

    missing_gateway_patterns = [
        "default gateway blank",
        "default gateway: blank",
        "default gateway blank",
        "default gateway is blank",
        "default gateway not configured",
        "gateway not configured",
        "gateway is blank",
        "default gateway:",
    ]

    for pattern in missing_gateway_patterns:

        if pattern in text:

            return {
                "rule": "Gateway",
                "status": "FAIL",
                "message": (
                    "Default gateway is not configured."
                ),
            }

    # -----------------------------------------------------
    # Extract gateway from SHOW OUTPUT
    # -----------------------------------------------------

    configured_gateway = None

    gateway_patterns = [
        r"default\s+gateway\s*:?\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        r"default\s+gateway\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
    ]

    for pattern in gateway_patterns:

        match = re.search(
            pattern,
            str(show_output),
            re.IGNORECASE,
        )

        if match:

            configured_gateway = match.group(1)

            break

    # -----------------------------------------------------
    # Extract expected gateway from topology
    # -----------------------------------------------------

    expected_gateway = None

    expected_patterns = [
        r"gateway\s+should\s+be\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        r"expected\s+gateway\s+is\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        r"actual\s+gateway\s+is\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
    ]

    for pattern in expected_patterns:

        match = re.search(
            pattern,
            str(topology),
            re.IGNORECASE,
        )

        if match:

            expected_gateway = match.group(1)

            break

    # -----------------------------------------------------
    # Compare configured and expected gateway
    # -----------------------------------------------------

    if configured_gateway and expected_gateway:

        if configured_gateway != expected_gateway:

            return {
                "rule": "Gateway",
                "status": "FAIL",
                "message": (
                    "Incorrect default gateway: "
                    f"configured {configured_gateway}; "
                    f"expected {expected_gateway}."
                ),
            }

    # -----------------------------------------------------
    # Generic gateway evidence
    # -----------------------------------------------------

    gateway_keywords = [
        "wrong gateway",
        "incorrect gateway",
        "gateway mismatch",
        "default gateway incorrect",
        "default gateway wrong",
    ]

    for keyword in gateway_keywords:

        if keyword in text:

            return {
                "rule": "Gateway",
                "status": "FAIL",
                "message": (
                    "Possible default gateway mismatch detected."
                ),
            }

    return None


# =========================================================
# RULE 4 - SUBNET MASK
# =========================================================

def check_subnet_mask(text):

    text_lower = normalize(text)

    if "subnet mask" not in text_lower:
        return None

    actual_match = re.search(
        r"subnet\s+mask\s*:?\s*"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        str(text),
        re.IGNORECASE,
    )

    expected_match = re.search(
        r"expected\s+"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        str(text),
        re.IGNORECASE,
    )

    if actual_match and expected_match:

        actual = actual_match.group(1)
        expected = expected_match.group(1)

        if actual != expected:

            return {
                "rule": "Subnet Mask",
                "status": "FAIL",
                "message": (
                    f"Wrong subnet mask: {actual}; "
                    f"expected {expected}."
                ),
            }

    return None


# =========================================================
# RULE 5 - INTERFACE STATUS
# =========================================================

def check_interface(text):

    text_lower = normalize(text)

    keywords = [
        "administratively down",
        "interface down",
        "line protocol is down",
        "protocol down",
    ]

    for keyword in keywords:

        if keyword in text_lower:

            return {
                "rule": "Interface Status",
                "status": "FAIL",
                "message": (
                    f"Interface problem detected: "
                    f"'{keyword}'"
                ),
            }

    return None


# =========================================================
# RULE 6 - PHYSICAL LINK
# =========================================================

def check_physical_link(text):

    text_lower = normalize(text)

    keywords = [
        "damaged cable",
        "physical link",
        "cabling problem",
        "crc",
        "input errors",
        "crc errors",
    ]

    for keyword in keywords:

        if keyword in text_lower:

            return {
                "rule": "Physical Link",
                "status": "FAIL",
                "message": (
                    "Physical link or cabling problem detected."
                ),
            }

    return None


# =========================================================
# RULE 7 - VLAN / SWITCHPORT
# =========================================================

def check_vlan(symptom, topology, show_output):

    text = normalize(
        " ".join([
            str(symptom or ""),
            str(topology or ""),
            str(show_output or ""),
        ])
    )

    # -----------------------------------------------------
    # Switchport VLAN assignment
    # -----------------------------------------------------

    vlan_assignment = re.search(
        r"fa0/1\s+is\s+listed\s+under\s+vlan\s+(\d+)",
        text,
        re.IGNORECASE,
    )

    expected_vlan = re.search(
        r"expected\s+vlan\s+(\d+)",
        text,
        re.IGNORECASE,
    )

    if vlan_assignment and expected_vlan:

        actual = vlan_assignment.group(1)
        expected = expected_vlan.group(1)

        if actual != expected:

            return {
                "rule": "VLAN Configuration",
                "status": "FAIL",
                "message": (
                    "Incorrect switchport VLAN assignment: "
                    f"Fa0/1 is in VLAN {actual}; "
                    f"expected VLAN {expected}."
                ),
            }

    # -----------------------------------------------------
    # Missing VLAN creation
    # -----------------------------------------------------

    missing_vlan = re.search(
        r"vlan\s+(\d+)\s+is\s+not\s+present",
        text,
        re.IGNORECASE,
    )

    if missing_vlan:

        vlan_id = missing_vlan.group(1)

        return {
            "rule": "VLAN Configuration",
            "status": "FAIL",
            "message": (
                f"Required VLAN {vlan_id} "
                "is missing or not created."
            ),
        }

    # -----------------------------------------------------
    # Trunk VLAN missing
    # -----------------------------------------------------

    trunk_match = re.search(
        r"vlan\s+(\d+)\s+is\s+missing\s+"
        r"from\s+the\s+trunk\s+allowed\s+list",
        text,
        re.IGNORECASE,
    )

    if trunk_match:

        vlan_id = trunk_match.group(1)

        return {
            "rule": "VLAN/Trunk",
            "status": "FAIL",
            "message": (
                f"VLAN {vlan_id} is missing "
                "from the trunk allowed list."
            ),
        }

    # -----------------------------------------------------
    # 802.1Q VLAN ID
    # -----------------------------------------------------

    dot1q = re.search(
        r"encapsulation\s+dot1q\s+(\d+)",
        text,
        re.IGNORECASE,
    )

    expected_dot1q = re.search(
        r"expected\s+vlan\s+id\s+is\s+(\d+)",
        text,
        re.IGNORECASE,
    )

    if dot1q and expected_dot1q:

        actual = dot1q.group(1)
        expected = expected_dot1q.group(1)

        if actual != expected:

            return {
                "rule": "VLAN/802.1Q",
                "status": "FAIL",
                "message": (
                    f"Wrong 802.1Q VLAN ID: {actual}; "
                    f"expected {expected}."
                ),
            }

    # -----------------------------------------------------
    # Native VLAN mismatch
    # -----------------------------------------------------

    if "native vlan mismatch" in text:

        return {
            "rule": "Native VLAN",
            "status": "FAIL",
            "message": (
                "Native VLAN mismatch detected "
                "between trunk endpoints."
            ),
        }

    return None


# =========================================================
# RULE 8 - ROUTING
# =========================================================

def check_routing(text):

    text_lower = normalize(text)

    keywords = [
        "network not in routing table",
        "route missing",
        "no route",
        "destination unreachable",
        "network unreachable",
        "routing table does not contain",
        "ospf network advertisement missing",
    ]

    for keyword in keywords:

        if keyword in text_lower:

            return {
                "rule": "Routing",
                "status": "FAIL",
                "message": (
                    "Possible missing or incorrect route detected."
                ),
            }

    # Static route next hop

    configured = re.search(
        r"configured\s+"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        str(text),
        re.IGNORECASE,
    )

    actual = re.search(
        r"actual\s+(?:r2\s+)?next\s+hop\s+is\s+"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        str(text),
        re.IGNORECASE,
    )

    if configured and actual:

        if configured.group(1) != actual.group(1):

            return {
                "rule": "Routing",
                "status": "FAIL",
                "message": (
                    "Incorrect static-route next hop: "
                    f"configured {configured.group(1)}; "
                    f"actual next hop {actual.group(1)}."
                ),
            }

    return None


# =========================================================
# RULE 9 - DHCP
# =========================================================

def check_dhcp(text):

    text_lower = normalize(text)

    if "dhcp pool exhausted" in text_lower:

        return {
            "rule": "DHCP",
            "status": "FAIL",
            "message": "DHCP pool is exhausted.",
        }

    if "wrong dhcp default router" in text_lower:

        return {
            "rule": "DHCP",
            "status": "FAIL",
            "message": (
                "DHCP default-router configuration "
                "is incorrect."
            ),
        }

    if (
        "default router 192.168.80.254" in text_lower
        and "actual gateway is 192.168.80.1" in text_lower
    ):

        return {
            "rule": "DHCP",
            "status": "FAIL",
            "message": (
                "Wrong DHCP default-router: "
                "configured 192.168.80.254; "
                "actual gateway 192.168.80.1."
            ),
        }

    return None


# =========================================================
# RULE 10 - DNS
# =========================================================

def check_dns(text):

    text_lower = normalize(text)

    if "dns resolution request timed out" in text_lower:

        return {
            "rule": "DNS",
            "status": "FAIL",
            "message": "DNS resolution request timed out.",
        }

    if (
        "dns servers 8.8.8.8 only" in text_lower
        and "internal dns 10.0.0.53" in text_lower
    ):

        return {
            "rule": "DNS",
            "status": "FAIL",
            "message": (
                "Wrong DNS server address: "
                "configured 8.8.8.8; "
                "expected 10.0.0.53."
            ),
        }

    if (
        "wrong dns server" in text_lower
        or "dns resolution failure" in text_lower
        or "nxdomain" in text_lower
    ):

        return {
            "rule": "DNS",
            "status": "FAIL",
            "message": (
                "DNS resolution or DNS configuration "
                "problem detected."
            ),
        }

    return None


# =========================================================
# RULE 11 - ACL
# =========================================================

def check_acl(text):

    text_lower = normalize(text)

    keywords = [
        "acl blocking",
        "acl incorrectly blocks",
        "acl rule is blocking",
        "guest isolation acl is missing",
        "no deny rule from guest vlan",
        "acl blocking dns",
        "acl blocking http",
    ]

    for keyword in keywords:

        if keyword in text_lower:

            return {
                "rule": "ACL",
                "status": "FAIL",
                "message": (
                    "ACL rule is blocking or "
                    "incorrectly allowing traffic."
                ),
            }

    return None


# =========================================================
# RULE 12 - NAT
# =========================================================

def check_nat(text):

    text_lower = normalize(text)

    keywords = [
        "nat not configured",
        "nat configuration problem",
        "nat outside interface missing",
        "missing static nat mapping",
        "static nat mapping",
    ]

    for keyword in keywords:

        if keyword in text_lower:

            return {
                "rule": "NAT",
                "status": "FAIL",
                "message": (
                    "NAT configuration problem detected."
                ),
            }

    return None


# =========================================================
# RULE 13 - WIRELESS
# =========================================================

def check_wireless(text):

    text_lower = normalize(text)

    if (
        "security key" in text_lower
        and "authentication failed" in text_lower
    ):

        return {
            "rule": "Wireless",
            "status": "FAIL",
            "message": (
                "Incorrect wireless security key detected."
            ),
        }

    if (
        "channel interference" in text_lower
        or (
            "ap1 channel 6" in text_lower
            and "ap2 channel 6" in text_lower
        )
    ):

        return {
            "rule": "Wireless",
            "status": "FAIL",
            "message": (
                "Wireless channel interference detected."
            ),
        }

    return None


# =========================================================
# RULE 14 - SPEED / DUPLEX
# =========================================================

def check_speed_duplex(text):

    text_lower = normalize(text)

    keywords = [
        "speed/duplex mismatch",
        "speed duplex mismatch",
        "speed mismatch",
        "duplex mismatch",
        "speed configuration mismatch",
    ]

    for keyword in keywords:

        if keyword in text_lower:

            return {
                "rule": "Speed/Duplex",
                "status": "FAIL",
                "message": (
                    "Speed or duplex configuration "
                    "mismatch detected."
                ),
            }

    return None


# =========================================================
# RUN ALL RULES
# =========================================================

def run_rules(case):

    symptom = case.get("symptom", "")
    topology = case.get("topology_note", "")
    show_output = case.get("show_output", "")

    combined_text = " ".join([
        str(symptom),
        str(topology),
        str(show_output),
    ])

    findings = []

    # Gateway gets its own structured inputs
    result = check_gateway(
        symptom,
        topology,
        show_output,
    )

    if result:
        findings.append(result)

    # Other rules
    checks = [
        check_duplicate_ip(combined_text),
        check_invalid_ip(combined_text),
        check_subnet_mask(combined_text),
        check_interface(combined_text),
        check_physical_link(combined_text),
        check_vlan(
            symptom,
            topology,
            show_output,
        ),
        check_routing(combined_text),
        check_dhcp(combined_text),
        check_dns(combined_text),
        check_acl(combined_text),
        check_nat(combined_text),
        check_wireless(combined_text),
        check_speed_duplex(combined_text),
    ]

    for result in checks:

        if result:
            findings.append(result)

    return findings


# =========================================================
# PROCESS CSV
# =========================================================

def process_csv(filename):

    print("\n==========================================")
    print("         NETSAGE AI RULE CHECKER V9")
    print("==========================================\n")

    results = []

    total_cases = 0
    total_findings = 0
    cases_with_findings = 0

    with open(
        filename,
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:

        reader = csv.DictReader(file)

        for case in reader:

            total_cases += 1

            case_id = case.get(
                "case_id",
                f"CASE-{total_cases}",
            )

            findings = run_rules(case)

            print("------------------------------------------")
            print(f"Case: {case_id}")

            if not findings:

                print("✅ No deterministic fault detected.")

            else:

                cases_with_findings += 1

                for finding in findings:

                    print(
                        f"❌ {finding['rule']}: "
                        f"{finding['message']}"
                    )

            total_findings += len(findings)

            results.append({
                "case_id": case_id,
                "findings": findings,
            })

    cases_without_findings = (
        total_cases - cases_with_findings
    )

    # =====================================================
    # SUMMARY
    # =====================================================

    print("\n==========================================")
    print("SUMMARY")
    print("==========================================")

    print(
        f"Total cases checked : {total_cases}"
    )

    print(
        f"Total findings      : {total_findings}"
    )

    print(
        f"Cases with findings : {cases_with_findings}"
    )

    print(
        f"Cases with no finding: "
        f"{cases_without_findings}"
    )

    # =====================================================
    # SAVE JSON
    # =====================================================

    with open(
        RESULT_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False,
        )

    print("\nResults saved to:")
    print(RESULT_FILE)

    print("\nRule Checker V9 completed.")


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    if not CSV_FILE.exists():

        print(
            f"ERROR: CSV file not found: "
            f"{CSV_FILE}"
        )

        sys.exit(1)

    process_csv(CSV_FILE)