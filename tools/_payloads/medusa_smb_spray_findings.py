"""medusa_smb_spray - findings rules."""


def rule_critical_login(s):
    succ = s.get("medusa_smb_successes") or []
    if not succ:
        return None
    user_list = ", ".join(sorted({x.get("user", "?") for x in succ}))[:200]
    return {
        "name": f"Weak SMB password proven - {len(succ)} valid credential(s) on port "
                f"{s.get('medusa_smb_spray_target_port', 445)}",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (f"Medusa smbnt spray succeeded against user(s): {user_list}. "
                     f"{s.get('medusa_smb_spray_attempts', 0)} total attempts. "
                     "(Passwords redacted per VulnusLab privacy policy.)"),
        "remediation": (
            "1. Rotate the compromised account password(s) and check Windows Event ID 4624/4625 + Samba auth.log for unauthorized access. "
            "2. Enforce a 14-char password GPO + Account Lockout (5 fails -> 30 min) - none of the cracked passwords would have survived. "
            "3. Disable SMBv1, require SMB signing for all clients (LANMAN server: 'EnableSecuritySignature' = 1). "
            "4. Never expose port 445 to the public internet - SMB belongs behind a VPN or ZTNA tunnel. "
            "5. For Samba: tighten 'restrict anonymous = 2', 'server signing = mandatory', 'min protocol = SMB3'."
        ),
    }


def rule_input_missing(s):
    if not s.get("medusa_input_missing"):
        return None
    return {
        "name": "Medusa SMB spray skipped - no userlist/passlist supplied",
        "severity": "INFO",
        "evidence": "This scanner requires options.userlist + options.passlist on the request body.",
        "remediation": ("Re-run with options.userlist + options.passlist populated. "
                        "Recommend SecLists top-5 Windows usernames + breach top-20 passwords."),
        "cwe": "CWE-1006",
    }


def rule_port_closed(s):
    if not s.get("medusa_smb_port_closed"):
        return None
    return {
        "name": f"SMB service unreachable on port {s.get('medusa_smb_spray_target_port', 445)}",
        "severity": "INFO",
        "evidence": "Medusa reported the SMB port closed / connection refused.",
        "remediation": ("Confirm whether SMB should be reachable. If port 445 is intentionally not exposed, "
                        "no action needed - that is the recommended posture."),
        "cwe": "CWE-1006",
    }


def rule_lockout_hit(s):
    if not s.get("medusa_smb_lockout_hit"):
        return None
    return {
        "name": "SMB account lockout policy is active - reduces brute risk",
        "severity": "POSITIVE",
        "evidence": "Medusa output reports account lockout / disabled mid-spray.",
        "remediation": ("Account Lockout Policy is doing its job. Keep threshold tight "
                        "(5 fails / 30 min) and monitor 4740 events to spot password sprays in your SIEM."),
        "cwe": "CWE-307",
    }


def rule_binary_missing(s):
    if not s.get("medusa_smb_spray_error"):
        return None
    if "medusa binary not installed" not in str(s.get("medusa_smb_spray_error")):
        return None
    return {
        "name": "Medusa binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('medusa') returned None.",
        "remediation": "Install medusa: apt install medusa (Debian/Kali) or build from JoMo-Kun/medusa.",
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("medusa_smb_spray_total"):
        return None
    if s.get("medusa_input_missing"):
        return None
    if s.get("medusa_smb_port_closed"):
        return None
    if s.get("medusa_smb_spray_error"):
        return None
    if s.get("medusa_smb_lockout_hit"):
        # lockout rule already emitted POSITIVE - don't double-emit
        return None
    attempts = s.get("medusa_smb_spray_attempts") or 0
    if not attempts:
        return None
    return {
        "name": "SMB withstood Medusa password spray",
        "severity": "POSITIVE",
        "evidence": (f"{attempts} attempt(s) over "
                     f"{s.get('medusa_smb_spray_users_tried', 0)} user(s) on port "
                     f"{s.get('medusa_smb_spray_target_port', 445)} - no valid login."),
        "remediation": ("Keep enforcing GPO + SMB signing. Re-spray quarterly with breach corpus updates."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


MEDUSA_SMB_SPRAY_FINDING_RULES = [
    rule_critical_login,
    rule_input_missing,
    rule_port_closed,
    rule_lockout_hit,
    rule_binary_missing,
    rule_positive,
]
