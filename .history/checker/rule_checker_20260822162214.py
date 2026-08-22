import csv
import json
import ipaddress
import re
import sys
from pathlib import Path


# =========================================================
# NETSAGE AI - RULE CHECKER V11
# =========================================================

sys.stdout.reconfigure(encoding="utf-8")

CSV_FILE = Path("data/cases_v3_final_1.csv")
RESULT_FILE = Path("checker_results.json")


# =========================================================
# HELPERS
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
    if not text:
        return []

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return re.findall(pattern, str(text))


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def contains_any(text, keywords):
    text = normalize(text)
    return any(keyword in text for keyword in keywords)


# =========================================================
# RULE 1 - DUPLICATE IP
# =========================================================

def check_duplicate_ip(text):

    text = normalize(text)

    keywords = [
        "duplicate ip",
        "same ip",
        "ip conflict",
        "address conflict",
        "two pcs have the same ip",
        "two hosts have the same ip",
        "two devices have the same ip",
        "duplicate address",
    ]

    if contains_any(text, keywords):
        return {
            "rule": "Duplicate IP",
            "status": "FAIL",
            "message": "IP conflict indicated by network evidence.",
        }

    return None


# =========================================================
# RULE 2 - INVALID IP
# =========================================================

def check_invalid_ip(text):

    ips = extract_ips(text)

    invalid = [
        ip for ip in ips
        if not valid_ip(ip)
    ]

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

def check_gateway(topology, show_output):

    topology_raw = str(topology)
    show_raw = str(show_output)

    topology_text = normalize(topology_raw)
    show_text = normalize(show_raw)

    # -----------------------------------------------------
    # Missing gateway
    # -----------------------------------------------------

    missing_patterns = [
        "default gateway: blank",
        "default gateway blank",
        "default gateway is blank",
        "default gateway: none",
        "default gateway none",
        "default gateway not configured",
        "gateway not configured",
        "gateway is blank",
    ]

    if contains_any(show_text, missing_patterns):

        return {
            "rule": "Gateway",
            "status": "FAIL",
            "message": "Default gateway is not configured.",
        }

    # -----------------------------------------------------
    # Extract configured gateway
    # -----------------------------------------------------

    configured_gateway = None

    configured_patterns = [
        r"default\s+gateway\s*:?\s*"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

        r"default\s+gateway\s+"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
    ]

    for pattern in configured_patterns:

        match = re.search(
            pattern,
            show_raw,
            re.IGNORECASE,
        )

        if match:
            configured_gateway = match.group(1)
            break

    # -----------------------------------------------------
    # Extract expected gateway
    # -----------------------------------------------------

    expected_gateway = None

    expected_patterns = [
        r"gateway\s+should\s+be\s+"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

        r"expected\s+gateway\s+is\s+"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",

        r"actual\s+gateway\s+is\s+"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
    ]

    for pattern in expected_patterns:

        match = re.search(
            pattern,
            topology_raw,
            re.IGNORECASE,
        )

        if match:
            expected_gateway = match.group(1)
            break

    # -----------------------------------------------------
    # Compare configured and expected
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
    # Generic evidence
    # -----------------------------------------------------

    keywords = [
        "wrong gateway",
        "incorrect gateway",
        "gateway mismatch",
        "default gateway incorrect",
        "default gateway wrong",
        "cannot reach default gateway",
    ]

    if contains_any(
        topology_text + " " + show_text,
        keywords,
    ):

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

    text = normalize(text)

    if not any(
        word in text
        for word in [
            "subnet mask",
            "wrong subnet",
            "incorrect subnet",
            "mask mismatch",
            "incorrect dhcp subnet mask",
        ]
    ):
        return None

    actual_match = re.search(
        r"(?:subnet\s+mask|mask)\s*:?\s*"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        text,
        re.IGNORECASE,
    )

    expected_match = re.search(
        r"expected\s+"
        r"(?:subnet\s+mask\s+)?"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        text,
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

    return {
        "rule": "Subnet Mask",
        "status": "FAIL",
        "message": "Subnet mask configuration problem detected.",
    }


# =========================================================
# RULE 5 - INTERFACE
# =========================================================

def check_interface(text):

    text = normalize(text)

    keywords = [
        "administratively down",
        "interface down",
        "line protocol is down",
        "protocol down",
        "interface shutdown",
        "shutdown interface",
        "interface is shutdown",
    ]

    for keyword in keywords:

        if keyword in text:

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

    text = normalize(text)

    keywords = [
        "damaged cable",
        "physical link",
        "physical link problem",
        "cabling problem",
        "cable problem",
        "input errors",
        "crc",
        "crc errors",
        "intermittently loses network connection",
        "link errors",
        "packet errors",
    ]

    if contains_any(text, keywords):

        return {
            "rule": "Physical Link",
            "status": "FAIL",
            "message": (
                "Physical link or cabling problem detected."
            ),
        }

    return None


# =========================================================
# RULE 7 - VLAN
# =========================================================

def check_vlan(symptom, topology, show_output):

    symptom = normalize(symptom)
    topology = normalize(topology)
    show = normalize(show_output)

    text = " ".join([
        symptom,
        topology,
        show,
    ])

    # -----------------------------------------------------
    # Wrong switchport VLAN
    # -----------------------------------------------------

    if (
        (
            "access port in vlan 10" in text
            or "should be an access port in vlan 10" in text
        )
        and "listed under vlan 1" in text
    ):

        return {
            "rule": "VLAN Configuration",
            "status": "FAIL",
            "message": (
                "Incorrect switchport VLAN assignment: "
                "Fa0/1 is in VLAN 1; expected VLAN 10."
            ),
        }

    # -----------------------------------------------------
    # VLAN missing / creation
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

    if contains_any(
        text,
        [
            "missing vlan creation",
            "vlan does not exist",
            "vlan missing",
            "unknown vlan",
            "vlan not found",
        ],
    ):

        return {
            "rule": "VLAN Configuration",
            "status": "FAIL",
            "message": (
                "Required VLAN is missing or not created."
            ),
        }

    # -----------------------------------------------------
    # Trunk allowed VLAN
    # -----------------------------------------------------

    trunk_vlan = re.search(
        r"vlan\s+(\d+)\s+is\s+missing\s+"
        r"(?:from\s+)?the\s+trunk\s+allowed\s+list",
        text,
        re.IGNORECASE,
    )

    if trunk_vlan:

        vlan_id = trunk_vlan.group(1)

        return {
            "rule": "VLAN/Trunk",
            "status": "FAIL",
            "message": (
                f"VLAN {vlan_id} is missing "
                "from the trunk allowed list."
            ),
        }

    # -----------------------------------------------------
    # Allowed VLAN absent
    # -----------------------------------------------------

    if (
        "trunk vlan not allowed" in text
        or "vlan absent" in text
        or "vlan 30 absent" in text
        or "vlan 50 absent" in text
        or "missing from the trunk allowed list" in text
        or "required vlan missing from trunk" in text
    ):

        return {
            "rule": "VLAN/Trunk",
            "status": "FAIL",
            "message": (
                "Required VLAN is missing from "
                "the trunk allowed list."
            ),
        }

    # -----------------------------------------------------
    # 802.1Q
    # -----------------------------------------------------

    dot1q = re.search(
        r"encapsulation\s+dot1q\s+(\d+)",
        text,
        re.IGNORECASE,
    )

    expected_dot1q = re.search(
        r"expected\s+(?:vlan\s+id|vlan\s+identifier)"
        r"\s+(?:is\s+)?(\d+)",
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
    # Native VLAN
    # -----------------------------------------------------

    if (
        "native vlan mismatch" in text
        or "native vlan mismatch detected" in text
    ):

        return {
            "rule": "Native VLAN",
            "status": "FAIL",
            "message": (
                "Native VLAN mismatch detected "
                "between trunk endpoints."
            ),
        }

    # -----------------------------------------------------
    # Wrong VLAN ID
    # -----------------------------------------------------

    if (
        "wrong 802.1q vlan id" in text
        or "wrong vlan id" in text
    ):

        return {
            "rule": "VLAN/802.1Q",
            "status": "FAIL",
            "message": (
                "Incorrect 802.1Q VLAN ID detected."
            ),
        }

    return None


# =========================================================
# RULE 8 - ROUTING
# =========================================================

def check_routing(text):

    text = normalize(text)

    keywords = [
        "missing static route",
        "route missing",
        "no route",
        "network not in routing table",
        "destination unreachable",
        "network unreachable",
        "routing table does not contain",
        "ospf network advertisement missing",
        "cannot reach headquarters",
        "branch lan cannot reach headquarters",
    ]

    if contains_any(text, keywords):

        return {
            "rule": "Routing",
            "status": "FAIL",
            "message": (
                "Possible missing or incorrect route detected."
            ),
        }

    # -----------------------------------------------------
    # Static next hop
    # -----------------------------------------------------

    configured = re.search(
        r"(?:via|configured)\s+"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        text,
        re.IGNORECASE,
    )

    actual = re.search(
        r"actual\s+(?:r2\s+)?next\s+hop\s+(?:is\s+)?"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        text,
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

    text = normalize(text)

    # -----------------------------------------------------
    # Pool exhaustion
    # -----------------------------------------------------

    pool_keywords = [
        "dhcp pool exhausted",
        "dhcp pool is exhausted",
        "pool exhausted",
        "no addresses available",
        "no available addresses",
        "address pool exhausted",
        "dhcp address pool exhausted",
        "dhcp pool has no free addresses",
        "dhcp pool has no available addresses",
    ]

    if contains_any(text, pool_keywords):

        return {
            "rule": "DHCP",
            "status": "FAIL",
            "message": "DHCP pool is exhausted.",
        }

    # -----------------------------------------------------
    # Wrong DHCP default router
    # -----------------------------------------------------

    configured = re.search(
        r"default[\s-]?router\s+"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        text,
        re.IGNORECASE,
    )

    actual_gateway = re.search(
        r"actual\s+gateway\s+(?:is\s+)?"
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        text,
        re.IGNORECASE,
    )

    if configured and actual_gateway:

        if configured.group(1) != actual_gateway.group(1):

            return {
                "rule": "DHCP",
                "status": "FAIL",
                "message": (
                    "Wrong DHCP default-router: "
                    f"configured {configured.group(1)}; "
                    f"actual gateway {actual_gateway.group(1)}."
                ),
            }

    # Generic DHCP default-router evidence

    if contains_any(
        text,
        [
            "wrong dhcp default router",
            "wrong dhcp default-router",
            "dhcp default router option",
            "dhcp default-router option",
            "default-router configuration",
            "default router configuration",
        ],
    ):

        return {
            "rule": "DHCP",
            "status": "FAIL",
            "message": (
                "DHCP default-router configuration "
                "is incorrect."
            ),
        }

    # -----------------------------------------------------
    # DHCP subnet mask
    # -----------------------------------------------------

    if (
        "dhcp" in text
        and "subnet mask" in text
        and (
            "incorrect" in text
            or "wrong" in text
            or "expected" in text
        )
    ):

        return {
            "rule": "DHCP",
            "status": "FAIL",
            "message": (
                "Incorrect DHCP subnet mask detected."
            ),
        }

    return None


# =========================================================
# RULE 10 - DNS
# =========================================================

def check_dns(text):

    text = normalize(text)

    keywords = [
        "dns resolution failure",
        "dns resolution request timed out",
        "dns timeout",
        "dns query timed out",
        "dns server unreachable",
        "dns resolution failed",
        "cannot resolve hostname",
        "hostname resolution failed",
    ]

    if contains_any(text, keywords):

        return {
            "rule": "DNS",
            "status": "FAIL",
            "message": (
                "DNS resolution or DNS configuration "
                "problem detected."
            ),
        }

    if (
        "dns servers 8.8.8.8 only" in text
        or (
            "8.8.8.8" in text
            and "internal dns 10.0.0.53" in text
        )
        or "wrong dns server address" in text
        or "nxdomain" in text
    ):

        return {
            "rule": "DNS",
            "status": "FAIL",
            "message": (
                "Wrong DNS server address or "
                "DNS resolution problem detected."
            ),
        }

    return None


# =========================================================
# RULE 11 - ACL
# =========================================================

def check_acl(text):

    text = normalize(text)

    keywords = [
        "acl blocking",
        "acl blocking http",
        "acl blocking dns",
        "acl incorrectly blocks",
        "acl incorrectly block",
        "acl rule is blocking",
        "acl rule blocks",
        "acl rule blocking",
        "acl blocking traffic",
        "access list blocking",
        "access-list blocking",
        "guest isolation acl",
        "missing guest isolation acl",
        "no deny rule from guest vlan",
        "permit rule allows traffic",
        "acl incorrectly allowing",
        "acl incorrectly allow",
        "missing acl",
    ]

    if contains_any(text, keywords):

        return {
            "rule": "ACL",
            "status": "FAIL",
            "message": (
                "ACL rule is blocking or incorrectly "
                "allowing traffic."
            ),
        }

    return None


# =========================================================
# RULE 12 - NAT
# =========================================================

def check_nat(text):

    text = normalize(text)

    keywords = [
        "nat not configured",
        "nat configuration problem",
        "nat outside interface missing",
        "nat outside interface is missing",
        "missing static nat mapping",
        "static nat mapping missing",
        "static nat mapping",
        "nat mapping missing",
        "inside interface missing",
        "nat inside interface missing",
        "outside interface missing",
        "ip nat",
        "nat configuration",
    ]

    # Avoid treating generic "NAT configuration" as a fault
    # unless there is fault-related evidence.
    fault_words = [
        "missing",
        "not configured",
        "incorrect",
        "wrong",
        "problem",
        "failed",
        "failure",
        "absent",
        "not working",
    ]

    if (
        contains_any(text, keywords)
        and contains_any(text, fault_words)
    ):

        return {
            "rule": "NAT",
            "status": "FAIL",
            "message": (
                "NAT configuration problem detected."
            ),
        }

    if contains_any(
        text,
        [
            "nat not configured",
            "nat outside interface missing",
            "missing static nat mapping",
            "nat mapping missing",
            "inside interface missing",
        ],
    ):

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

    text = normalize(text)

    # -----------------------------------------------------
    # Security key
    # -----------------------------------------------------

    if (
        "security key" in text
        and (
            "authentication failed" in text
            or "different key" in text
            or "incorrect key" in text
            or "wrong key" in text
        )
    ):

        return {
            "rule": "Wireless",
            "status": "FAIL",
            "message": (
                "Incorrect wireless security key detected."
            ),
        }

    if (
        "wireless client cannot join" in text
        and (
            "authentication failed" in text
            or "wpa2" in text
            or "security key" in text
        )
    ):

        return {
            "rule": "Wireless",
            "status": "FAIL",
            "message": (
                "Incorrect wireless security key detected."
            ),
        }

    # -----------------------------------------------------
    # Channel interference
    # -----------------------------------------------------

    if (
        "channel interference" in text
        or "overlapping 2.4 ghz channels" in text
        or "high channel utilization" in text
        or "wireless interference" in text
        or (
            "ap1 channel 6" in text
            and "ap2 channel 6" in text
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

    text = normalize(text)

    keywords = [
        "speed/duplex mismatch",
        "speed duplex mismatch",
        "speed mismatch",
        "duplex mismatch",
        "speed configuration mismatch",
        "duplex configuration mismatch",
        "speed and duplex mismatch",
        "speed or duplex mismatch",
        "speed is",
        "duplex is",
    ]

    if contains_any(text, keywords):

        # Avoid false positives from unrelated interface text.
        if (
            "mismatch" in text
            or "different" in text
            or "incorrect" in text
            or "wrong" in text
        ):

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

    checks = [

        # Gateway
        check_gateway(
            topology,
            show_output,
        ),

        # IP
        check_duplicate_ip(combined_text),
        check_invalid_ip(combined_text),

        # Network
        check_subnet_mask(combined_text),
        check_interface(combined_text),
        check_physical_link(combined_text),

        # VLAN
        check_vlan(
            symptom,
            topology,
            show_output,
        ),

        # Routing
        check_routing(combined_text),

        # Services
        check_dhcp(combined_text),
        check_dns(combined_text),

        # Security
        check_acl(combined_text),
        check_nat(combined_text),

        # Wireless
        check_wireless(combined_text),

        # Physical configuration
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
    print("         NETSAGE AI RULE CHECKER V11")
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

                print(
                    "OK No deterministic fault detected."
                )

            else:

                cases_with_findings += 1

                for finding in findings:

                    symbol = (
                        "FAIL"
                        if finding["status"] == "FAIL"
                        else "OK"
                    )

                    print(
                        f"{symbol} {finding['rule']}: "
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

    print("\nRule Checker V11 completed.")


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