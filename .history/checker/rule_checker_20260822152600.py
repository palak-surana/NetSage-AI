import csv
import ipaddress
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------
# Windows UTF-8 support
# ---------------------------------------------------------

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

CSV_FILE = Path("data/cases_v3_final_1.csv")
RESULT_FILE = Path("checker_results.json")


# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------

def extract_ips(text):
    """Extract IPv4 addresses from text."""

    if not text:
        return []

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    return re.findall(pattern, text)


def valid_ip(ip):
    """Check whether an IPv4 address is valid."""

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def add_finding(findings, rule, message, evidence=""):
    """Add a deterministic finding."""

    findings.append({
        "rule": rule,
        "status": "FAIL",
        "message": message,
        "evidence": evidence
    })


# ---------------------------------------------------------
# Rule 1: Duplicate IP
# ---------------------------------------------------------

def check_duplicate_ip(text, findings):

    lower = text.lower()

    conflict_words = [
        "duplicate ip",
        "same ip",
        "ip conflict",
        "address conflict",
        "two pcs have the same ip",
        "two hosts have the same ip",
        "two devices have the same ip"
    ]

    if any(word in lower for word in conflict_words):

        ips = extract_ips(text)

        # Ignore network addresses when possible
        usable_ips = []

        for ip in ips:
            try:
                address = ipaddress.ip_address(ip)

                if not address.is_unspecified:
                    usable_ips.append(ip)

            except ValueError:
                pass

        duplicates = []

        for ip in set(usable_ips):

            if usable_ips.count(ip) > 1:
                duplicates.append(ip)

        if duplicates:

            add_finding(
                findings,
                "Duplicate IP",
                f"Confirmed duplicate IP conflict: {', '.join(duplicates)}",
                "Multiple devices/evidence indicate the same IP address."
            )

        else:

            add_finding(
                findings,
                "Duplicate IP",
                "IP conflict indicated by network evidence.",
                "Evidence explicitly indicates an IP conflict."
            )


# ---------------------------------------------------------
# Rule 2: Invalid IP
# ---------------------------------------------------------

def check_invalid_ip(text, findings):

    ips = extract_ips(text)

    invalid = []

    for ip in ips:

        if not valid_ip(ip):
            invalid.append(ip)

    if invalid:

        add_finding(
            findings,
            "Invalid IP",
            f"Invalid IP address detected: {', '.join(invalid)}",
            f"Detected IP values: {', '.join(invalid)}"
        )


# ---------------------------------------------------------
# Rule 3: Subnet Mask
# ---------------------------------------------------------

def check_subnet_mask(text, findings):

    lower = text.lower()

    # Explicit mask comparison
    mask_pattern = (
        r"(?:subnet mask|mask)\s*[:=]?\s*"
        r"(255\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:expected|should be)\s*"
        r"(255\.\d+\.\d+\.\d+)"
    )

    match = re.search(mask_pattern, lower)

    if match:

        actual_mask = match.group(1)
        expected_mask = match.group(2)

        if actual_mask != expected_mask:

            add_finding(
                findings,
                "Subnet Mask",
                (
                    f"Wrong subnet mask: {actual_mask}; "
                    f"expected {expected_mask}"
                ),
                match.group(0)
            )

            return

    keywords = [
        "wrong subnet mask",
        "incorrect subnet mask",
        "invalid subnet mask",
        "mask mismatch",
        "subnet mask mismatch",
        "wrong mask",
        "incorrect mask"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Subnet Mask",
                f"Possible subnet mask problem: '{keyword}'",
                keyword
            )

            return


# ---------------------------------------------------------
# Rule 4: Gateway
# ---------------------------------------------------------

def check_gateway(text, findings):

    lower = text.lower()

    # Explicit gateway mismatch
    keywords = [
        "wrong gateway",
        "incorrect gateway",
        "gateway mismatch",
        "default gateway incorrect",
        "default gateway wrong",
        "gateway should be"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Gateway",
                "Possible default gateway mismatch detected.",
                keyword
            )

            return

    # Blank gateway
    if "default gateway: blank" in lower:

        add_finding(
            findings,
            "Gateway",
            "Default gateway is not configured.",
            "Default Gateway: blank"
        )

        return

    # Gateway outside subnet
    network_match = re.search(
        r"(\d+\.\d+\.\d+\.\d+)/(\d+)",
        text
    )

    gateway_match = re.search(
        r"(?:gateway|default gateway)[\s:=]+"
        r"(\d+\.\d+\.\d+\.\d+)",
        lower
    )

    if network_match and gateway_match:

        try:

            network = ipaddress.ip_network(
                f"{network_match.group(1)}/{network_match.group(2)}",
                strict=False
            )

            gateway = ipaddress.ip_address(
                gateway_match.group(1)
            )

            if gateway not in network:

                add_finding(
                    findings,
                    "Gateway",
                    (
                        f"Gateway {gateway} is outside "
                        f"the host subnet {network}"
                    ),
                    f"Network: {network}; Gateway: {gateway}"
                )

        except ValueError:
            pass


# ---------------------------------------------------------
# Rule 5: Interface Down
# ---------------------------------------------------------

def check_interface(text, findings):

    lower = text.lower()

    keywords = [
        "administratively down",
        "line protocol is down",
        "interface down",
        "status down"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Interface Status",
                f"Interface problem detected: '{keyword}'",
                keyword
            )

            return


# ---------------------------------------------------------
# Rule 6: Speed / Duplex
# ---------------------------------------------------------

def check_speed_duplex(text, findings):

    lower = text.lower()

    speed_problem = (
        "10mb/s" in lower
        and "100mb/s" in lower
    )

    duplex_problem = (
        "duplex half" in lower
        and "100mb/s full" in lower
    )

    mismatch_words = [
        "speed/duplex mismatch",
        "duplex mismatch",
        "speed mismatch"
    ]

    if speed_problem or duplex_problem:

        add_finding(
            findings,
            "Speed/Duplex",
            "Speed or duplex configuration mismatch detected.",
            text
        )

        return

    for word in mismatch_words:

        if word in lower:

            add_finding(
                findings,
                "Speed/Duplex",
                "Speed/duplex mismatch detected.",
                word
            )

            return


# ---------------------------------------------------------
# Rule 7: VLAN
# ---------------------------------------------------------

def check_vlan(text, findings):

    lower = text.lower()

    # VLAN does not exist
    missing_vlan_words = [
        "vlan does not exist",
        "vlan missing",
        "unknown vlan",
        "vlan not found",
        "vlan is not present"
    ]

    for word in missing_vlan_words:

        if word in lower:

            add_finding(
                findings,
                "VLAN Configuration",
                "Required VLAN is missing.",
                word
            )

            return

    # VLAN absent from trunk
    trunk_match = re.search(
        r"allowed vlans?\s*[:=]?\s*([0-9,\- ]+)",
        lower
    )

    required_match = re.search(
        r"(?:vlan|required vlan)\s+(\d+)",
        lower
    )

    if trunk_match and required_match:

        allowed_text = trunk_match.group(1)
        required_vlan = required_match.group(1)

        allowed_vlans = re.findall(
            r"\d+",
            allowed_text
        )

        if required_vlan not in allowed_vlans:

            add_finding(
                findings,
                "VLAN/Trunk",
                (
                    f"VLAN {required_vlan} is missing "
                    f"from the trunk allowed list."
                ),
                (
                    f"Allowed VLANs: {allowed_text}; "
                    f"Required VLAN: {required_vlan}"
                )
            )

            return

    # Generic explicit VLAN problem
    vlan_keywords = [
        "incorrect vlan",
        "wrong vlan assignment",
        "wrong switchport vlan"
    ]

    for word in vlan_keywords:

        if word in lower:

            add_finding(
                findings,
                "VLAN Configuration",
                "Incorrect VLAN configuration detected.",
                word
            )

            return


# ---------------------------------------------------------
# Rule 8: Native VLAN
# ---------------------------------------------------------

def check_native_vlan(text, findings):

    lower = text.lower()

    if "native vlan mismatch" in lower:

        add_finding(
            findings,
            "Native VLAN",
            "Native VLAN mismatch detected between trunk endpoints.",
            "Native VLAN mismatch warning."
        )

        return

    match = re.search(
        r"native vlan\s+(\d+).*?"
        r"native vlan\s+(\d+)",
        lower
    )

    if match:

        first = match.group(1)
        second = match.group(2)

        if first != second:

            add_finding(
                findings,
                "Native VLAN",
                f"Native VLAN mismatch: {first} vs {second}",
                match.group(0)
            )


# ---------------------------------------------------------
# Rule 9: Routing
# ---------------------------------------------------------

def check_routing(text, findings):

    lower = text.lower()

    routing_words = [
        "no route",
        "route missing",
        "network not in routing table",
        "routing table does not contain",
        "destination unreachable",
        "network unreachable"
    ]

    for word in routing_words:

        if word in lower:

            add_finding(
                findings,
                "Routing",
                "Possible missing or incorrect route detected.",
                word
            )

            return

    # Missing OSPF network
    if (
        "router ospf" in lower
        and "does not include" in lower
    ):

        add_finding(
            findings,
            "OSPF/Routing",
            "OSPF network advertisement is missing.",
            "OSPF network statement does not include the new subnet."
        )

        return

    # Wrong next hop
    if "next hop" in lower:

        add_finding(
            findings,
            "Routing",
            "Possible incorrect static-route next hop.",
            "Evidence references an incorrect next hop."
        )


# ---------------------------------------------------------
# Rule 10: NAT
# ---------------------------------------------------------

def check_nat(text, findings):

    lower = text.lower()

    nat_keywords = [
        "no static nat",
        "no static mapping",
        "missing static nat",
        "nat outside interface missing",
        "no ip nat outside",
        "no ip nat inside",
        "nat translations: empty"
    ]

    for word in nat_keywords:

        if word in lower:

            add_finding(
                findings,
                "NAT",
                "NAT configuration problem detected.",
                word
            )

            return


# ---------------------------------------------------------
# Rule 11: ACL
# ---------------------------------------------------------

def check_acl(text, findings):

    lower = text.lower()

    acl_keywords = [
        "deny tcp",
        "deny udp",
        "deny ip",
        "missing guest isolation acl",
        "acl blocking",
        "acl incorrectly blocks"
    ]

    for word in acl_keywords:

        if word in lower:

            add_finding(
                findings,
                "ACL",
                "ACL rule is blocking or missing required traffic.",
                word
            )

            return


# ---------------------------------------------------------
# Rule 12: DHCP
# ---------------------------------------------------------

def check_dhcp(text, findings):

    lower = text.lower()

    if "254/254 addresses leased" in lower:

        add_finding(
            findings,
            "DHCP",
            "DHCP pool is exhausted.",
            "254/254 addresses are leased."
        )

        return

    if "default-router" in lower:

        add_finding(
            findings,
            "DHCP",
            "DHCP default-router configuration should be verified.",
            "DHCP configuration contains default-router information."
        )


# ---------------------------------------------------------
# Rule 13: DNS
# ---------------------------------------------------------

def check_dns(text, findings):

    lower = text.lower()

    dns_keywords = [
        "nslookup",
        "dns server",
        "dns servers",
        "request timed out",
        "nxdomain",
        "dns queries time out"
    ]

    for word in dns_keywords:

        if word in lower:

            # Only report if there is an actual DNS failure indication
            failure_words = [
                "timed out",
                "nxdomain",
                "cannot",
                "wrong dns",
                "dns resolution failure",
                "queries time out"
            ]

            if any(failure in lower for failure in failure_words):

                add_finding(
                    findings,
                    "DNS",
                    "DNS resolution or DNS configuration problem detected.",
                    word
                )

                return


# ---------------------------------------------------------
# Run All Rules
# ---------------------------------------------------------

def run_rules(case):

    # IMPORTANT:
    # Do NOT use expected_fault or evidence_expected.
    # Those are the answer key.
    #
    # The checker only uses observed evidence.

    symptom = str(case.get("symptom", ""))
    topology = str(case.get("topology_note", ""))
    show_output = str(case.get("show_output", ""))

    combined_text = " ".join([
        symptom,
        topology,
        show_output
    ])

    findings = []

    check_duplicate_ip(combined_text, findings)
    check_invalid_ip(combined_text, findings)
    check_subnet_mask(combined_text, findings)
    check_gateway(combined_text, findings)
    check_interface(combined_text, findings)
    check_speed_duplex(combined_text, findings)
    check_vlan(combined_text, findings)
    check_native_vlan(combined_text, findings)
    check_routing(combined_text, findings)
    check_nat(combined_text, findings)
    check_acl(combined_text, findings)
    check_dhcp(combined_text, findings)
    check_dns(combined_text, findings)

    return findings


# ---------------------------------------------------------
# Process CSV
# ---------------------------------------------------------

def process_csv(filename):

    print("\n==========================================")
    print("         NETSAGE AI RULE CHECKER V2")
    print("==========================================\n")

    if not filename.exists():

        print("ERROR: CSV file not found.")
        print(f"Expected: {filename}")

        return

    results = []

    total_cases = 0
    total_findings = 0

    with open(
        filename,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        for case in reader:

            total_cases += 1

            case_id = case.get(
                "case_id",
                f"CASE-{total_cases}"
            )

            findings = run_rules(case)

            case_result = {
                "case_id": case_id,
                "findings": findings,
                "finding_count": len(findings)
            }

            results.append(case_result)

            print("------------------------------------------")
            print(f"Case: {case_id}")

            if findings:

                for finding in findings:

                    print(
                        f"❌ {finding['rule']}: "
                        f"{finding['message']}"
                    )

                total_findings += len(findings)

            else:

                print("✅ No deterministic fault detected.")

    # -----------------------------------------------------
    # Save JSON results
    # -----------------------------------------------------

    with open(
        RESULT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False
        )

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    print("\n==========================================")
    print("SUMMARY")
    print("==========================================")

    print(
        f"Total cases checked : {total_cases}"
    )

    print(
        f"Total findings      : {total_findings}"
    )

    cases_with_findings = sum(
        1
        for result in results
        if result["finding_count"] > 0
    )

    print(
        f"Cases with findings : {cases_with_findings}"
    )

    print(
        f"Cases with no finding: "
        f"{total_cases - cases_with_findings}"
    )

    print("\nResults saved to:")
    print(RESULT_FILE)

    print("\nRule Checker V2 completed.")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    process_csv(CSV_FILE)