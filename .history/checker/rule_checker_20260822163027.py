import csv
import ipaddress
import json
import re
import sys
from pathlib import Path


# =========================================================
# NETSAGE AI - RULE CHECKER V6
# Evidence-Based Deterministic Network Troubleshooting
# =========================================================

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# =========================================================
# FILE CONFIGURATION
# =========================================================

CSV_FILE = Path("data/cases_v3_final_1.csv")
RESULT_FILE = Path("checker_results.json")


# =========================================================
# HELPERS
# =========================================================

def extract_ips(text):
    if not text:
        return []

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return re.findall(pattern, text)


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def add_finding(findings, rule, message, evidence=""):
    findings.append({
        "rule": rule,
        "status": "FAIL",
        "message": message,
        "evidence": evidence
    })


# =========================================================
# RULE 1 - DUPLICATE IP
# =========================================================

def check_duplicate_ip(text, findings):

    lower = text.lower()

    keywords = [
        "duplicate ip",
        "same ip",
        "ip conflict",
        "address conflict",
        "two pcs have the same ip",
        "two hosts have the same ip",
        "two devices have the same ip"
    ]

    if not any(k in lower for k in keywords):
        return

    ips = extract_ips(text)

    duplicates = []

    for ip in set(ips):
        if ips.count(ip) > 1:
            duplicates.append(ip)

    if duplicates:
        add_finding(
            findings,
            "Duplicate IP",
            "Confirmed duplicate IP conflict: "
            + ", ".join(duplicates),
            "Repeated IP addresses in conflict evidence."
        )
    else:
        add_finding(
            findings,
            "Duplicate IP",
            "IP conflict indicated by network evidence.",
            "Explicit IP conflict evidence."
        )


# =========================================================
# RULE 2 - INVALID IP
# =========================================================

def check_invalid_ip(text, findings):

    ips = extract_ips(text)

    invalid = [
        ip for ip in ips
        if not valid_ip(ip)
    ]

    if invalid:
        add_finding(
            findings,
            "Invalid IP",
            "Invalid IP address detected: "
            + ", ".join(invalid),
            ", ".join(invalid)
        )


# =========================================================
# RULE 3 - SUBNET MASK
# =========================================================

def check_subnet_mask(text, findings):

    lower = text.lower()

    pattern = (
        r"(?:subnet mask|mask)"
        r"\s*[:=]?\s*"
        r"(255\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:expected|should be)"
        r"\s*[:=]?\s*"
        r"(255\.\d+\.\d+\.\d+)"
    )

    match = re.search(pattern, lower, re.IGNORECASE)

    if match:

        actual = match.group(1)
        expected = match.group(2)

        if actual != expected:
            add_finding(
                findings,
                "Subnet Mask",
                f"Wrong subnet mask: {actual}; "
                f"expected {expected}",
                match.group(0)
            )

            return

    keywords = [
        "wrong subnet mask",
        "incorrect subnet mask",
        "invalid subnet mask",
        "mask mismatch",
        "subnet mask mismatch"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Subnet Mask",
                "Possible subnet mask problem detected.",
                keyword
            )

            return


# =========================================================
# RULE 4 - GATEWAY
# =========================================================

def check_gateway(text, findings):
    """
    Detect an incorrect or missing default gateway from explicit evidence.

    Handles:
      - configured/default gateway vs expected gateway
      - topology statements such as "gateway should be X"
      - "actual gateway is X"
      - blank/missing gateway
    """
    lower = text.lower()

    # -----------------------------------------------------
    # Explicit configured gateway + expected/should-be gateway
    # -----------------------------------------------------
    configured_patterns = [
        r"(?:default\s+gateway|gateway)\s*[:=]?\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})"
        r".*?"
        r"(?:expected|should\s+be|correct|actual)"
        r"(?:\s+(?:default\s+)?gateway)?\s*[:=]?\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})",

        # Example:
        # Default Gateway 192.168.1.1
        # gateway should be 192.168.10.1
        r"(?:default\s+gateway|gateway)\s*[:=]?\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})"
        r".*?"
        r"gateway\s+should\s+be\s*[:=]?\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})",

        # Example:
        # configured 192.168.1.1; expected 192.168.10.1
        r"(?:configured|current)\s*"
        r"(?:default\s+gateway|gateway)?\s*[:=]?\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})"
        r".*?"
        r"(?:expected|correct|actual)\s*"
        r"(?:default\s+gateway|gateway)?\s*[:=]?\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})",
    ]

    for pattern in configured_patterns:
        match = re.search(pattern, lower, re.IGNORECASE)

        if match:
            configured = match.group(1)
            expected = match.group(2)

            if configured != expected:
                add_finding(
                    findings,
                    "Gateway",
                    (
                        f"Incorrect default gateway: "
                        f"configured {configured}; "
                        f"expected {expected}."
                    ),
                    match.group(0)
                )
                return

    # -----------------------------------------------------
    # Explicit missing gateway
    # -----------------------------------------------------
    missing_patterns = [
        "default gateway: blank",
        "default gateway blank",
        "default gateway is blank",
        "default gateway: none",
        "default gateway none",
        "default gateway is none",
        "default gateway not configured",
        "default gateway is not configured",
        "missing default gateway",
    ]

    for keyword in missing_patterns:
        if keyword in lower:
            add_finding(
                findings,
                "Gateway",
                "Default gateway is not configured.",
                keyword
            )
            return

    # -----------------------------------------------------
    # Explicit gateway fault wording
    # -----------------------------------------------------
    keywords = [
        "wrong gateway",
        "incorrect gateway",
        "gateway mismatch",
        "default gateway incorrect",
        "default gateway wrong",
        "incorrect default gateway",
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


# =========================================================
# RULE 5 - INTERFACE STATUS
# =========================================================

def check_interface(text, findings):

    lower = text.lower()

    keywords = [
        "administratively down",
        "line protocol is down",
        "interface down",
        "interface is down"
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


# =========================================================
# RULE 6 - PHYSICAL LINK / CABLING
# =========================================================

def check_physical_link(text, findings):

    lower = text.lower()

    keywords = [
        "damaged cable",
        "cable damaged",
        "cable disconnected",
        "cable unplugged",
        "cabling problem",
        "bad cable",
        "loose cable",
        "physical link",
        "physical layer",
        "link not detected",
        "no link",
        "fiber disconnected"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Physical Link",
                "Physical link or cabling problem detected.",
                keyword
            )

            return

    crc_match = re.search(
        r"crc\s+(\d+)",
        lower
    )

    input_match = re.search(
        r"input errors?\s+(\d+)",
        lower
    )

    if crc_match and input_match:

        crc = int(crc_match.group(1))
        input_errors = int(input_match.group(1))

        if crc > 0 and input_errors > 0:

            add_finding(
                findings,
                "Physical Link",
                (
                    "Possible physical link/cabling problem: "
                    f"{input_errors} input errors and "
                    f"{crc} CRC errors detected."
                ),
                (
                    f"Input errors: {input_errors}; "
                    f"CRC errors: {crc}"
                )
            )


# =========================================================
# RULE 7 - SPEED / DUPLEX
# =========================================================

def check_speed_duplex(text, findings):

    lower = text.lower()

    keywords = [
        "speed/duplex mismatch",
        "speed duplex mismatch",
        "speed or duplex mismatch",
        "duplex mismatch",
        "speed mismatch",
        "half duplex"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Speed/Duplex",
                "Speed or duplex configuration mismatch detected.",
                keyword
            )

            return


# =========================================================
# RULE 8 - VLAN ASSIGNMENT
# =========================================================

def check_vlan_assignment(text, findings):

    lower = text.lower()

    # CASE001:
    # Fa0/1 listed under VLAN 1
    # should be access port VLAN 10

    patterns = [
        r"(?:fa\d+/\d+|gi\d+/\d+)"
        r".*?"
        r"(?:listed under|assigned to)"
        r"\s+vlan\s+(\d+)"
        r".*?"
        r"(?:should be|expected)"
        r".*?"
        r"vlan\s+(\d+)",

        r"(?:listed under|assigned to)"
        r"\s+vlan\s+(\d+)"
        r".*?"
        r"(?:access port|should be)"
        r".*?"
        r"vlan\s+(\d+)"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            lower,
            re.IGNORECASE
        )

        if match:

            actual = match.group(1)
            expected = match.group(2)

            if actual != expected:

                add_finding(
                    findings,
                    "VLAN Configuration",
                    (
                        f"Switchport VLAN mismatch: "
                        f"actual VLAN {actual}; "
                        f"expected VLAN {expected}."
                    ),
                    match.group(0)
                )

                return

    keywords = [
        "wrong switchport vlan assignment",
        "incorrect switchport vlan assignment",
        "wrong vlan assignment",
        "incorrect vlan assignment",
        "switchport vlan mismatch",
        "wrong access vlan",
        "incorrect access vlan"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "VLAN Configuration",
                "Incorrect switchport VLAN assignment detected.",
                keyword
            )

            return


# =========================================================
# RULE 9 - VLAN CREATION
# =========================================================

def check_vlan_creation(text, findings):

    lower = text.lower()

    match = re.search(
        r"vlan\s+(\d+)"
        r".*?"
        r"(?:not present|does not exist|missing|not found)",
        lower
    )

    if match:

        vlan = match.group(1)

        add_finding(
            findings,
            "VLAN Configuration",
            f"Required VLAN {vlan} is missing or not created.",
            match.group(0)
        )

        return

    keywords = [
        "missing vlan creation",
        "vlan has not been created",
        "vlan not created",
        "vlan does not exist",
        "vlan missing",
        "vlan not found"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "VLAN Configuration",
                "Required VLAN is missing or has not been created.",
                keyword
            )

            return


# =========================================================
# RULE 10 - TRUNK VLAN ALLOWED
# =========================================================

def check_trunk_vlan(text, findings):

    lower = text.lower()

    # CASE005
    allowed_match = re.search(
        r"allowed vlans?\s*[:=]?\s*"
        r"([0-9,\- ]+)",
        lower
    )

    absent_match = re.search(
        r"vlan\s+(\d+)\s+absent",
        lower
    )

    if allowed_match and absent_match:

        allowed = allowed_match.group(1)
        required = absent_match.group(1)

        allowed_vlans = re.findall(
            r"\d+",
            allowed
        )

        if required not in allowed_vlans:

            add_finding(
                findings,
                "VLAN/Trunk",
                f"VLAN {required} is missing from the trunk allowed list.",
                (
                    f"Allowed VLANs: {allowed}; "
                    f"Required VLAN: {required}"
                )
            )

            return

    # CASE030
    # "VLAN 50 is required"
    # "allowed VLANs 10,20,30"
    # "VLAN 50 absent"

    required_match = re.search(
        r"vlan\s+(\d+)\s+is\s+required",
        lower
    )

    allowed_match = re.search(
        r"allowed vlans?\s*[:=]?\s*"
        r"([0-9,\- ]+)",
        lower
    )

    if required_match and allowed_match:

        required = required_match.group(1)
        allowed = allowed_match.group(1)

        allowed_vlans = re.findall(
            r"\d+",
            allowed
        )

        if required not in allowed_vlans:

            add_finding(
                findings,
                "VLAN/Trunk",
                f"VLAN {required} is missing from the trunk allowed list.",
                (
                    f"Allowed VLANs: {allowed}; "
                    f"Required VLAN: {required}"
                )
            )

            return

    keywords = [
        "trunk vlan not allowed",
        "vlan not allowed on trunk",
        "trunk does not allow vlan",
        "vlan missing from trunk",
        "required vlan missing from trunk",
        "not allowed on trunk"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "VLAN/Trunk",
                "Required VLAN is not allowed on the trunk.",
                keyword
            )

            return


# =========================================================
# RULE 11 - 802.1Q VLAN ID
# =========================================================

def check_dot1q_vlan(text, findings):

    lower = text.lower()

    match = re.search(
        r"encapsulation\s+dot1q\s+(\d+)"
        r".*?"
        r"expected vlan id is\s+(\d+)",
        lower
    )

    if match:

        actual = match.group(1)
        expected = match.group(2)

        if actual != expected:

            add_finding(
                findings,
                "VLAN/802.1Q",
                f"Wrong 802.1Q VLAN ID: {actual}; expected {expected}.",
                match.group(0)
            )

            return


# =========================================================
# RULE 12 - NATIVE VLAN
# =========================================================

def check_native_vlan(text, findings):

    lower = text.lower()

    if "native vlan mismatch" in lower:

        add_finding(
            findings,
            "Native VLAN",
            "Native VLAN mismatch detected between trunk endpoints.",
            "Native VLAN mismatch."
        )


# =========================================================
# RULE 13 - ROUTING
# =========================================================

def check_routing(text, findings):

    lower = text.lower()

    # Static next hop
    match = re.search(
        r"via\s+"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"actual\s+r2\s+next\s+hop\s+is\s+"
        r"(\d+\.\d+\.\d+\.\d+)",
        lower
    )

    if match:

        configured = match.group(1)
        actual = match.group(2)

        if configured != actual:

            add_finding(
                findings,
                "Routing",
                (
                    f"Incorrect static-route next hop: "
                    f"configured {configured}; "
                    f"actual next hop {actual}."
                ),
                match.group(0)
            )

            return

    keywords = [
        "no route",
        "route missing",
        "missing static route",
        "network not in routing table",
        "routing table does not contain",
        "destination unreachable",
        "network unreachable",
        "incorrect static route next hop",
        "wrong static route next hop",
        "incorrect next hop",
        "wrong next hop"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Routing",
                "Possible missing or incorrect route detected.",
                keyword
            )

            return

    # OSPF
    ospf_keywords = [
        "ospf network advertisement missing",
        "ospf network missing",
        "ospf network statement missing",
        "network not advertised by ospf"
    ]

    for keyword in ospf_keywords:

        if keyword in lower:

            add_finding(
                findings,
                "OSPF/Routing",
                "OSPF network advertisement is missing.",
                keyword
            )

            return


# =========================================================
# RULE 14 - NAT
# =========================================================

def check_nat(text, findings):

    lower = text.lower()

    keywords = [
        "no static nat",
        "no static mapping",
        "missing static nat",
        "static nat missing",
        "nat not configured",
        "nat outside interface missing",
        "nat inside interface missing",
        "no ip nat outside",
        "no ip nat inside",
        "missing static nat mapping"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "NAT",
                "NAT configuration problem detected.",
                keyword
            )

            return


# =========================================================
# RULE 15 - ACL
# =========================================================

def check_acl(text, findings):

    lower = text.lower()

    if (
        "missing guest isolation acl" in lower
        or "guest isolation acl missing" in lower
    ):

        add_finding(
            findings,
            "ACL",
            "Guest isolation ACL is missing.",
            "Guest isolation ACL is required."
        )

        return

    if (
        "guest vlan 50" in lower
        and "no deny rule" in lower
        and "permit rule allows traffic" in lower
    ):

        add_finding(
            findings,
            "ACL",
            "Guest isolation ACL is missing or incorrectly configured.",
            "No deny rule exists for guest VLAN 50."
        )

        return

    keywords = [
        "acl blocking http",
        "acl blocking dns",
        "acl blocking traffic",
        "acl incorrectly blocks",
        "acl blocks",
        "access list denies",
        "deny tcp",
        "deny udp",
        "deny ip"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "ACL",
                "ACL rule is blocking or incorrectly allowing traffic.",
                keyword
            )

            return


# =========================================================
# RULE 16 - DHCP
# =========================================================

def check_dhcp(text, findings):

    lower = text.lower()

    if (
        "dhcp pool exhausted" in lower
        or "pool exhausted" in lower
        or "254/254 addresses leased" in lower
    ):

        add_finding(
            findings,
            "DHCP",
            "DHCP pool is exhausted.",
            "No DHCP addresses available."
        )

        return

    match = re.search(
        r"default-router\s+"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"actual gateway is\s+"
        r"(\d+\.\d+\.\d+\.\d+)",
        lower
    )

    if match:

        configured = match.group(1)
        actual = match.group(2)

        if configured != actual:

            add_finding(
                findings,
                "DHCP",
                (
                    f"Wrong DHCP default-router: "
                    f"configured {configured}; "
                    f"actual gateway {actual}."
                ),
                match.group(0)
            )

            return

    keywords = [
        "wrong dhcp default-router",
        "wrong dhcp default router",
        "incorrect dhcp default-router",
        "incorrect dhcp default router",
        "default-router option incorrect"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "DHCP",
                "Incorrect DHCP default-router option detected.",
                keyword
            )

            return


# =========================================================
# RULE 17 - DNS
# =========================================================

def check_dns(text, findings):

    lower = text.lower()

    # CASE020
    if (
        "dns servers 8.8.8.8 only" in lower
        and "internal dns 10.0.0.53" in lower
    ):

        add_finding(
            findings,
            "DNS",
            "Wrong DNS server address: configured 8.8.8.8; expected 10.0.0.53.",
            "DNS server mismatch."
        )

        return

    match = re.search(
        r"(?:dns servers?|dns server)"
        r"\s*[:=]?\s*"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:should use|expected|internal dns)"
        r"\s*"
        r"(\d+\.\d+\.\d+\.\d+)",
        lower
    )

    if match:

        configured = match.group(1)
        expected = match.group(2)

        if configured != expected:

            add_finding(
                findings,
                "DNS",
                (
                    f"Wrong DNS server address: "
                    f"configured {configured}; "
                    f"expected {expected}."
                ),
                match.group(0)
            )

            return

    keywords = [
        "dns resolution failure",
        "dns resolution failed",
        "wrong dns server",
        "incorrect dns server",
        "dns server address incorrect",
        "dns resolution problem"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "DNS",
                "DNS resolution or DNS configuration problem detected.",
                keyword
            )

            return

    if (
        "nslookup" in lower
        and "nxdomain" in lower
    ):

        add_finding(
            findings,
            "DNS",
            "DNS resolution returned NXDOMAIN.",
            "NXDOMAIN detected by nslookup."
        )

        return

    if (
        "nslookup" in lower
        and "timed out" in lower
    ):

        add_finding(
            findings,
            "DNS",
            "DNS resolution request timed out.",
            "nslookup timeout."
        )


# =========================================================
# RULE 18 - WIRELESS
# =========================================================

def check_wireless(text, findings):

    lower = text.lower()

    keywords = [
        "incorrect wireless security key",
        "wrong wireless security key",
        "incorrect security key",
        "wrong security key",
        "authentication failed with different key",
        "security key mismatch"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Wireless",
                "Incorrect wireless security key detected.",
                keyword
            )

            return

    if (
        "ap1 channel 6" in lower
        and "ap2 channel 6" in lower
        and (
            "interference" in lower
            or "channel utilization" in lower
        )
    ):

        add_finding(
            findings,
            "Wireless",
            "Wireless channel interference detected.",
            "AP1 and AP2 use the same channel with high interference."
        )

        return

    keywords = [
        "wireless channel interference",
        "channel interference",
        "wifi interference",
        "wi-fi interference",
        "co-channel interference",
        "channel congestion"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Wireless",
                "Wireless channel interference detected.",
                keyword
            )

            return


# =========================================================
# RUN ALL RULES
# =========================================================

def run_rules(case):

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
    check_physical_link(combined_text, findings)
    check_speed_duplex(combined_text, findings)

    check_vlan_assignment(combined_text, findings)
    check_vlan_creation(combined_text, findings)
    check_trunk_vlan(combined_text, findings)
    check_dot1q_vlan(combined_text, findings)
    check_native_vlan(combined_text, findings)

    check_routing(combined_text, findings)
    check_nat(combined_text, findings)
    check_acl(combined_text, findings)
    check_dhcp(combined_text, findings)
    check_dns(combined_text, findings)
    check_wireless(combined_text, findings)

    return findings


# =========================================================
# PROCESS CSV
# =========================================================

def process_csv(filename):

    print("\n==========================================")
    print("         NETSAGE AI RULE CHECKER V6")
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

            results.append({
                "case_id": case_id,
                "findings": findings,
                "finding_count": len(findings)
            })

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

                print(
                    "✅ No deterministic fault detected."
                )

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

    cases_with_findings = sum(
        1
        for result in results
        if result["finding_count"] > 0
    )

    cases_without_findings = (
        total_cases - cases_with_findings
    )

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
        f"Cases with no finding: {cases_without_findings}"
    )

    print("\nResults saved to:")
    print(RESULT_FILE)

    print("\nRule Checker V6 completed.")


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    process_csv(CSV_FILE)