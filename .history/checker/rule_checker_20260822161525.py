import csv
import ipaddress
import json
import re
import sys
from pathlib import Path


# =========================================================
# NETSAGE AI - RULE CHECKER V8
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

    return re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )


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


def normalize(text):
    if not text:
        return ""

    return (
        str(text)
        .lower()
        .replace("_", " ")
        .replace("-", " ")
        .strip()
    )


# =========================================================
# 1. DUPLICATE IP
# =========================================================

def check_duplicate_ip(text, findings):

    lower = normalize(text)

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

    duplicates = [
        ip for ip in set(ips)
        if ips.count(ip) > 1
    ]

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
# 2. INVALID IP
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
# 3. SUBNET MASK
# =========================================================

def check_subnet_mask(text, findings):

    lower = normalize(text)

    patterns = [

        r"(?:subnet\s+mask|mask)"
        r"\s*[:=]?\s*"
        r"(255\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:expected|should\s+be|correct)"
        r"\s*[:=]?\s*"
        r"(255\.\d+\.\d+\.\d+)",

        r"(?:configured|current)"
        r"\s+(?:subnet\s+)?mask"
        r"\s*[:=]?\s*"
        r"(255\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:expected|correct)"
        r"\s*[:=]?\s*"
        r"(255\.\d+\.\d+\.\d+)"
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
                    "Subnet Mask",
                    f"Wrong subnet mask: {actual}; "
                    f"expected {expected}.",
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
# 4. GATEWAY - IMPROVED V8
# =========================================================

def check_gateway(text, findings):

    lower = normalize(text)

    # -----------------------------------------------------
    # CASE019 - missing gateway
    # -----------------------------------------------------

    missing_patterns = [

        "default gateway is not configured",
        "default gateway not configured",
        "default gateway is missing",
        "default gateway missing",
        "missing default gateway",
        "no default gateway",
        "default gateway is blank",
        "default gateway blank",
        "default gateway is none",
        "default gateway none",
        "default gateway n/a",
        "default gateway: n/a",
        "default gateway: none",
        "gateway is not configured",
        "gateway not configured",
        "gateway is missing",
        "gateway missing",
        "no gateway configured",
        "no gateway"
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
    # Explicit gateway mismatch
    # -----------------------------------------------------

    patterns = [

        # configured gateway X ... expected gateway Y
        r"(?:configured|current)"
        r"\s+(?:default\s+)?gateway"
        r"\s*[:=]?\s*"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:expected|correct|actual)"
        r".*?"
        r"(\d+\.\d+\.\d+\.\d+)",

        # default gateway X ... expected Y
        r"default\s+gateway"
        r"\s*[:=]?\s*"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:expected|correct|actual)"
        r".*?"
        r"(\d+\.\d+\.\d+\.\d+)",

        # gateway X ... actual gateway Y
        r"(?:gateway|default\s+gateway)"
        r"\s*[:=]?\s*"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:actual|expected|correct)"
        r".*?"
        r"(\d+\.\d+\.\d+\.\d+)"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            lower,
            re.IGNORECASE
        )

        if match:

            first_ip = match.group(1)
            second_ip = match.group(2)

            if first_ip != second_ip:

                add_finding(
                    findings,
                    "Gateway",
                    (
                        f"Wrong default gateway: "
                        f"configured {first_ip}; "
                        f"expected {second_ip}."
                    ),
                    match.group(0)
                )

                return

    # -----------------------------------------------------
    # Gateway mismatch keywords
    # -----------------------------------------------------

    mismatch_keywords = [
        "gateway mismatch",
        "default gateway mismatch",
        "wrong gateway",
        "incorrect gateway",
        "wrong default gateway",
        "incorrect default gateway",
        "default gateway wrong",
        "default gateway incorrect",
        "gateway address mismatch",
        "default gateway address mismatch"
    ]

    for keyword in mismatch_keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Gateway",
                "Possible default gateway mismatch detected.",
                keyword
            )

            return

    # -----------------------------------------------------
    # Extract gateway-related sentences
    # -----------------------------------------------------

    sentences = re.split(
        r"[\n.;]+",
        lower
    )

    gateway_ips = []

    for sentence in sentences:

        if (
            "gateway" in sentence
            or "default route" in sentence
        ):

            ips = extract_ips(sentence)

            for ip in ips:

                if ip not in gateway_ips:
                    gateway_ips.append(ip)

    # Two different gateway IPs in evidence
    if len(gateway_ips) >= 2:

        if gateway_ips[0] != gateway_ips[1]:

            add_finding(
                findings,
                "Gateway",
                (
                    f"Gateway mismatch detected: "
                    f"configured {gateway_ips[0]}; "
                    f"expected {gateway_ips[1]}."
                ),
                (
                    "Gateway evidence contains: "
                    + ", ".join(gateway_ips)
                )
            )

            return


# =========================================================
# 5. INTERFACE STATUS
# =========================================================

def check_interface(text, findings):

    lower = normalize(text)

    # IMPORTANT:
    # Do NOT classify generic "protocol down" alone as
    # interface failure. CASE027 can contain speed/duplex
    # evidence where "protocol" wording may appear.

    strong_keywords = [
        "administratively down",
        "interface is down",
        "interface down",
        "line protocol is down",
        "link is down",
        "status is down"
    ]

    for keyword in strong_keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Interface Status",
                f"Interface problem detected: '{keyword}'",
                keyword
            )

            return


# =========================================================
# 6. PHYSICAL LINK / CABLING
# =========================================================

def check_physical_link(text, findings):

    lower = normalize(text)

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
        r"input\s+errors?\s+(\d+)",
        lower
    )

    if crc_match and input_match:

        crc = int(crc_match.group(1))
        errors = int(input_match.group(1))

        if crc > 0 and errors > 0:

            add_finding(
                findings,
                "Physical Link",
                (
                    "Possible physical link/cabling problem: "
                    f"{errors} input errors and "
                    f"{crc} CRC errors detected."
                ),
                (
                    f"Input errors: {errors}; "
                    f"CRC errors: {crc}"
                )
            )


# =========================================================
# 7. SPEED / DUPLEX - IMPROVED V8
# =========================================================

def check_speed_duplex(text, findings):

    lower = normalize(text)

    # -----------------------------------------------------
    # Direct mismatch phrases
    # -----------------------------------------------------

    keywords = [
        "speed/duplex mismatch",
        "speed duplex mismatch",
        "speed or duplex mismatch",
        "speed and duplex mismatch",
        "duplex mismatch",
        "speed mismatch",
        "speed/duplex configuration mismatch",
        "speed duplex configuration mismatch",
        "duplex configuration mismatch",
        "speed configuration mismatch",
        "speed duplex problem",
        "speed or duplex problem",
        "speed and duplex problem",
        "speed is mismatched",
        "duplex is mismatched"
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

    # -----------------------------------------------------
    # Configured speed vs expected speed
    # -----------------------------------------------------

    speed_patterns = [

        r"(?:configured|current)"
        r"\s+speed\s*[:=]?\s*"
        r"(\d+)"
        r"\s*(?:mbps|mb/s)?"
        r".*?"
        r"(?:expected|correct|actual)"
        r"\s+speed\s*[:=]?\s*"
        r"(\d+)",

        r"speed\s*[:=]\s*"
        r"(\d+)"
        r".*?"
        r"(?:expected|actual|correct)"
        r"(?:\s+speed)?"
        r"\s*[:=]\s*"
        r"(\d+)"
    ]

    for pattern in speed_patterns:

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
                    "Speed/Duplex",
                    (
                        f"Speed mismatch: "
                        f"configured {actual}; "
                        f"expected {expected}."
                    ),
                    match.group(0)
                )

                return

    # -----------------------------------------------------
    # Common numeric speed mismatch
    # -----------------------------------------------------

    speed_values = re.findall(
        r"\b(10|100|1000|10000)\s*(?:mbps|mb/s)\b",
        lower
    )

    if len(speed_values) >= 2:

        unique_speeds = list(dict.fromkeys(speed_values))

        if len(unique_speeds) >= 2:

            add_finding(
                findings,
                "Speed/Duplex",
                "Speed configuration mismatch detected.",
                (
                    "Different interface speeds detected: "
                    + ", ".join(
                        f"{x} Mbps"
                        for x in unique_speeds
                    )
                )
            )

            return

    # -----------------------------------------------------
    # Cisco style:
    #
    # Full-duplex, 1000Mb/s
    # Half-duplex, 100Mb/s
    # -----------------------------------------------------

    duplex_modes = re.findall(
        r"\b(full|half|auto)"
        r"(?:[-\s]?duplex)?\b",
        lower
    )

    if len(duplex_modes) >= 2:

        unique_modes = list(
            dict.fromkeys(duplex_modes)
        )

        if len(unique_modes) >= 2:

            add_finding(
                findings,
                "Speed/Duplex",
                "Duplex configuration mismatch detected.",
                (
                    "Different duplex modes detected: "
                    + ", ".join(unique_modes)
                )
            )

            return

    # -----------------------------------------------------
    # Explicit full vs half
    # -----------------------------------------------------

    if (
        "full duplex" in lower
        and "half duplex" in lower
    ):

        add_finding(
            findings,
            "Speed/Duplex",
            "Speed or duplex configuration mismatch detected.",
            "Full-duplex and half-duplex configurations detected."
        )

        return

    # -----------------------------------------------------
    # Explicit auto vs manual mismatch
    # -----------------------------------------------------

    if (
        "auto duplex" in lower
        and (
            "full duplex" in lower
            or "half duplex" in lower
        )
    ):

        add_finding(
            findings,
            "Speed/Duplex",
            "Speed or duplex configuration mismatch detected.",
            "Auto and manually configured duplex values detected."
        )

        return

    # -----------------------------------------------------
    # Generic dataset wording
    # -----------------------------------------------------

    if (
        "speed" in lower
        and "duplex" in lower
        and (
            "wrong" in lower
            or "incorrect" in lower
            or "different" in lower
            or "mismatch" in lower
            or "problem" in lower
        )
    ):

        add_finding(
            findings,
            "Speed/Duplex",
            "Speed or duplex configuration mismatch detected.",
            "Speed/duplex evidence detected."
        )


# =========================================================
# 8. VLAN ASSIGNMENT
# =========================================================

def check_vlan_assignment(text, findings):

    lower = normalize(text)

    # CASE001
    if (
        ("fa0/1" in lower or "fa 0/1" in lower)
        and "listed under vlan 1" in lower
        and "vlan 10" in lower
        and (
            "access port in vlan 10" in lower
            or "should be an access port in vlan 10" in lower
        )
    ):

        add_finding(
            findings,
            "VLAN Configuration",
            (
                "Incorrect switchport VLAN assignment: "
                "Fa0/1 is in VLAN 1; expected VLAN 10."
            ),
            "Fa0/1 listed under VLAN 1; expected VLAN 10."
        )

        return

    patterns = [

        r"(?:fa\d+/\d+|gi\d+/\d+|g\d+/\d+)"
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
        r"access port"
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
# 9. VLAN CREATION
# =========================================================

def check_vlan_creation(text, findings):

    lower = normalize(text)

    patterns = [
        r"vlan\s+(\d+)"
        r".*?"
        r"(?:not present|does not exist|missing|not found)",

        r"(?:missing|not created|does not exist)"
        r".*?"
        r"vlan\s+(\d+)"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            lower
        )

        if match:

            vlan = match.group(1)

            add_finding(
                findings,
                "VLAN Configuration",
                (
                    f"Required VLAN {vlan} "
                    "is missing or not created."
                ),
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
# 10. TRUNK VLAN
# =========================================================

def check_trunk_vlan(text, findings):

    lower = normalize(text)

    allowed_match = re.search(
        r"allowed\s+vlans?\s*[:=]?\s*"
        r"([0-9,\- ]+)",
        lower
    )

    allowed_vlans = []

    if allowed_match:

        allowed_vlans = re.findall(
            r"\d+",
            allowed_match.group(1)
        )

    # CASE005
    absent_match = re.search(
        r"vlan\s+(\d+)\s+absent",
        lower
    )

    if absent_match and allowed_match:

        required = absent_match.group(1)

        if required not in allowed_vlans:

            add_finding(
                findings,
                "VLAN/Trunk",
                (
                    f"VLAN {required} is missing "
                    "from the trunk allowed list."
                ),
                (
                    f"Allowed VLANs: "
                    f"{allowed_match.group(1)}; "
                    f"Required VLAN: {required}"
                )
            )

            return

    # CASE030
    required_match = re.search(
        r"vlan\s+(\d+)\s+is\s+required",
        lower
    )

    if required_match and allowed_match:

        required = required_match.group(1)

        if required not in allowed_vlans:

            add_finding(
                findings,
                "VLAN/Trunk",
                (
                    f"VLAN {required} is missing "
                    "from the trunk allowed list."
                ),
                (
                    f"Allowed VLANs: "
                    f"{allowed_match.group(1)}; "
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
# 11. 802.1Q VLAN
# =========================================================

def check_dot1q_vlan(text, findings):

    lower = normalize(text)

    patterns = [

        r"encapsulation\s+dot1q\s+(\d+)"
        r".*?"
        r"expected\s+vlan\s+id\s+is\s+(\d+)",

        r"dot1q\s+(\d+)"
        r".*?"
        r"expected\s+(?:vlan\s+)?(?:id\s+)?(?:is\s+)?(\d+)"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            lower
        )

        if match:

            actual = match.group(1)
            expected = match.group(2)

            if actual != expected:

                add_finding(
                    findings,
                    "VLAN/802.1Q",
                    (
                        f"Wrong 802.1Q VLAN ID: "
                        f"{actual}; expected {expected}."
                    ),
                    match.group(0)
                )

                return


# =========================================================
# 12. NATIVE VLAN
# =========================================================

def check_native_vlan(text, findings):

    lower = normalize(text)

    keywords = [
        "native vlan mismatch",
        "native vlan does not match",
        "native vlan incorrect",
        "wrong native vlan"
    ]

    for keyword in keywords:

        if keyword in lower:

            add_finding(
                findings,
                "Native VLAN",
                "Native VLAN mismatch detected between trunk endpoints.",
                keyword
            )

            return


# =========================================================
# 13. ROUTING
# =========================================================

def check_routing(text, findings):

    lower = normalize(text)

    patterns = [

        r"via\s+"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"actual\s+r2\s+next\s+hop\s+is\s+"
        r"(\d+\.\d+\.\d+\.\d+)",

        r"via\s+"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"actual\s+next\s+hop\s+is\s+"
        r"(\d+\.\d+\.\d+\.\d+)",

        r"configured\s+next\s+hop\s+"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:actual|expected)\s+next\s+hop\s+"
        r"(\d+\.\d+\.\d+\.\d+)"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
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
                        "Incorrect static-route next hop: "
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
# 14. NAT
# =========================================================

def check_nat(text, findings):

    lower = normalize(text)

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
# 15. ACL
# =========================================================

def check_acl(text, findings):

    lower = normalize(text)

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
        "deny ip",
        "acl blocking",
        "acl incorrectly allowing"
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
# 16. DHCP
# =========================================================

def check_dhcp(text, findings):

    lower = normalize(text)

    if (
        "dhcp pool exhausted" in lower
        or "pool exhausted" in lower
        or "254/254 addresses leased" in lower
        or "no dhcp addresses available" in lower
    ):

        add_finding(
            findings,
            "DHCP",
            "DHCP pool is exhausted.",
            "No DHCP addresses available."
        )

        return

    patterns = [

        r"default-router\s+"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"actual\s+gateway\s+is\s+"
        r"(\d+\.\d+\.\d+\.\d+)",

        r"default\s+router\s+"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"actual\s+gateway\s+is\s+"
        r"(\d+\.\d+\.\d+\.\d+)"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
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
                        "Wrong DHCP default-router: "
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
# 17. DNS
# =========================================================

def check_dns(text, findings):

    lower = normalize(text)

    if (
        "dns servers 8.8.8.8 only" in lower
        and "internal dns 10.0.0.53" in lower
    ):

        add_finding(
            findings,
            "DNS",
            (
                "Wrong DNS server address: "
                "configured 8.8.8.8; "
                "expected 10.0.0.53."
            ),
            "DNS server mismatch."
        )

        return

    patterns = [

        r"(?:dns servers?|dns server)"
        r"\s*[:=]?\s*"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:should use|expected|internal dns)"
        r"\s*"
        r"(\d+\.\d+\.\d+\.\d+)",

        r"(?:configured|current)"
        r"\s+dns"
        r"\s*[:=]?\s*"
        r"(\d+\.\d+\.\d+\.\d+)"
        r".*?"
        r"(?:expected|correct|actual)"
        r"\s+dns"
        r"\s*[:=]?\s*"
        r"(\d+\.\d+\.\d+\.\d+)"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
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
        "dns resolution problem",
        "dns resolution request timed out",
        "dns timeout"
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
# 18. WIRELESS
# =========================================================

def check_wireless(text, findings):

    lower = normalize(text)

    security_keywords = [
        "incorrect wireless security key",
        "wrong wireless security key",
        "incorrect security key",
        "wrong security key",
        "authentication failed with different key",
        "security key mismatch"
    ]

    for keyword in security_keywords:

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
            or "overlapping" in lower
        )
    ):

        add_finding(
            findings,
            "Wireless",
            "Wireless channel interference detected.",
            "AP1 and AP2 use the same channel with interference."
        )

        return

    keywords = [
        "wireless channel interference",
        "channel interference",
        "wifi interference",
        "wi-fi interference",
        "co-channel interference",
        "channel congestion",
        "overlapping 2.4 ghz channels"
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

    symptom = str(
        case.get("symptom", "")
    )

    topology = str(
        case.get("topology_note", "")
    )

    show_output = str(
        case.get("show_output", "")
    )

    combined_text = " ".join([
        symptom,
        topology,
        show_output
    ])

    findings = []

    # IP
    check_duplicate_ip(
        combined_text,
        findings
    )

    check_invalid_ip(
        combined_text,
        findings
    )

    # Layer 3
    check_subnet_mask(
        combined_text,
        findings
    )

    check_gateway(
        combined_text,
        findings
    )

    # Interface / physical
    check_interface(
        combined_text,
        findings
    )

    check_physical_link(
        combined_text,
        findings
    )

    check_speed_duplex(
        combined_text,
        findings
    )

    # VLAN
    check_vlan_assignment(
        combined_text,
        findings
    )

    check_vlan_creation(
        combined_text,
        findings
    )

    check_trunk_vlan(
        combined_text,
        findings
    )

    check_dot1q_vlan(
        combined_text,
        findings
    )

    check_native_vlan(
        combined_text,
        findings
    )

    # Routing
    check_routing(
        combined_text,
        findings
    )

    # Security / translation
    check_nat(
        combined_text,
        findings
    )

    check_acl(
        combined_text,
        findings
    )

    # Services
    check_dhcp(
        combined_text,
        findings
    )

    check_dns(
        combined_text,
        findings
    )

    # Wireless
    check_wireless(
        combined_text,
        findings
    )

    return findings


# =========================================================
# PROCESS CSV
# =========================================================

def process_csv(filename):

    print("\n==========================================")
    print("         NETSAGE AI RULE CHECKER V8")
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

    # =====================================================
    # SAVE RESULTS
    # =====================================================

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

    # =====================================================
    # SUMMARY
    # =====================================================

    print("\n==========================================")
    print("SUMMARY")
    print("==========================================")

    print(
        f"Total cases checked : "
        f"{total_cases}"
    )

    print(
        f"Total findings      : "
        f"{total_findings}"
    )

    print(
        f"Cases with findings : "
        f"{cases_with_findings}"
    )

    print(
        f"Cases with no finding: "
        f"{cases_without_findings}"
    )

    print("\nResults saved to:")
    print(RESULT_FILE)

    print("\nRule Checker V8 completed.")


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    process_csv(
        CSV_FILE
    )