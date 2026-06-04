"""ncrack_rdp_spray - findings rules."""


def rule_critical_login(s):
    succ = s.get("ncrack_rdp_successes") or []
    if not succ:
        return None
    user_list = ", ".join(sorted({x.get("user", "?") for x in succ}))[:200]
    return {
        "name": f"Weak RDP password proven - {len(succ)} valid credential(s) on port "
                f"{s.get('ncrack_rdp_spray_target_port', 3389)}",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (f"Ncrack spray succeeded against user(s): {user_list}. "
                     f"{s.get('ncrack_rdp_spray_attempts', 0)} total attempts. "
                     "(Passwords redacted per VulnusLab privacy policy.)"),
        "remediation": (
            "1. Rotate compromised RDP account password(s) immediately and check Windows Security log for unauthorized RDP logons. "
            "2. Enforce 14-char+ passphrases via GPO and enable Account Lockout Policy (5 fails -> 15 min). "
            "3. Disable RDP on public interfaces - put it behind an RDS Gateway, VPN, or ZTNA tunnel. "
            "4. Enable NLA (Network Level Authentication) + MFA via Duo / Microsoft Authenticator. "
            "5. Limit RDP source IPs via Windows Firewall to admin jump boxes only."
        ),
    }


def rule_input_missing(s):
    if not s.get("ncrack_input_missing"):
        return None
    return {
        "name": "Ncrack RDP spray skipped - no userlist/passlist supplied",
        "severity": "INFO",
        "evidence": ("This scanner requires options.userlist + options.passlist "
                     "(newline-separated strings) on the request body."),
        "remediation": ("Re-run with options.userlist + options.passlist populated. "
                        "Recommend top-5 Windows admin usernames + breach corpus top-20 passwords."),
        "cwe": "CWE-1006",
    }


def rule_port_closed(s):
    if not s.get("ncrack_rdp_port_closed"):
        return None
    return {
        "name": f"RDP service unreachable on port {s.get('ncrack_rdp_spray_target_port', 3389)}",
        "severity": "INFO",
        "evidence": "Ncrack reported the RDP port closed / host down. Spray could not run.",
        "remediation": ("If RDP is intentionally not exposed externally, no action needed. "
                        "If RDP should be reachable, verify firewall rules + Network Level Authentication binding."),
        "cwe": "CWE-1006",
    }


def rule_binary_missing(s):
    if not s.get("ncrack_rdp_spray_error"):
        return None
    if "ncrack binary not installed" not in str(s.get("ncrack_rdp_spray_error")):
        return None
    return {
        "name": "Ncrack binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('ncrack') returned None.",
        "remediation": "Install ncrack: apt install ncrack (Debian/Kali) or build from Nmap project.",
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("ncrack_rdp_spray_total"):
        return None
    if s.get("ncrack_input_missing"):
        return None
    if s.get("ncrack_rdp_port_closed"):
        return None
    if s.get("ncrack_rdp_spray_error"):
        return None
    attempts = s.get("ncrack_rdp_spray_attempts") or 0
    if not attempts:
        return None
    return {
        "name": "RDP withstood Ncrack password spray",
        "severity": "POSITIVE",
        "evidence": (f"{attempts} attempt(s) over "
                     f"{s.get('ncrack_rdp_spray_users_tried', 0)} user(s) on port "
                     f"{s.get('ncrack_rdp_spray_target_port', 3389)} - no valid login."),
        "remediation": ("Keep enforcing strong-password GPO + NLA. Re-spray quarterly with "
                        "fresh breach corpus (passwords leak constantly)."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


NCRACK_RDP_SPRAY_FINDING_RULES = [
    rule_critical_login,
    rule_input_missing,
    rule_port_closed,
    rule_binary_missing,
    rule_positive,
]
