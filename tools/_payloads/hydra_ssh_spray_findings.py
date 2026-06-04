"""hydra_ssh_spray - findings rules.

Severity model:
  CRITICAL - any successful SSH login (weak password proven in production)
  INFO     - hydra missing / port closed / no input supplied (transparency)
  POSITIVE - spray ran, 0 successes (good password policy or lockout)
"""


def rule_critical_login(s):
    succ = s.get("hydra_ssh_successes") or []
    if not succ:
        return None
    user_list = ", ".join(sorted({x.get("user", "?") for x in succ}))[:200]
    return {
        "name": f"Weak SSH password proven - {len(succ)} valid credential(s) on port "
                f"{s.get('hydra_ssh_spray_target_port', 22)}",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (f"Hydra spray succeeded against user(s): {user_list}. "
                     f"{s.get('hydra_ssh_spray_attempts', 0)} total attempts. "
                     "(Passwords redacted in evidence per VulnusLab privacy policy.)"),
        "remediation": (
            "1. Rotate the compromised account password(s) immediately. "
            "2. Enforce a minimum 14-char passphrase OR require SSH key auth only (PasswordAuthentication no). "
            "3. Deploy fail2ban (3 fails -> 30 min ban) or change SSH port + enable PermitRootLogin no. "
            "4. Enable MFA via PAM/Duo for any human SSH access. "
            "5. Re-run this scan after fixes - any successful login means another rotation is overdue."
        ),
    }


def rule_input_missing(s):
    if not s.get("hydra_input_missing"):
        return None
    return {
        "name": "Hydra SSH spray skipped - no userlist/passlist supplied",
        "severity": "INFO",
        "evidence": ("This scanner requires options.userlist + options.passlist "
                     "(newline-separated strings) on the request. Without them no "
                     "spray attempts are made."),
        "remediation": (
            "Re-run with options.userlist + options.passlist populated. Example: "
            "use SecLists xato-net-10-million-usernames-top-1000.txt for users and "
            "rockyou.txt-top-1000 for passwords. Keep wordlists small (<=10 users, "
            "<=25 passwords) to avoid lockout."
        ),
        "cwe": "CWE-1006",
    }


def rule_port_closed(s):
    if not s.get("hydra_ssh_port_closed"):
        return None
    return {
        "name": f"SSH service unreachable on port {s.get('hydra_ssh_spray_target_port', 22)}",
        "severity": "INFO",
        "evidence": ("Hydra reported the SSH port closed / connection refused. "
                     "Spray could not run."),
        "remediation": ("Confirm the SSH service is exposed on the expected port. "
                        "If SSH is intentionally not exposed externally, no action needed."),
        "cwe": "CWE-1006",
    }


def rule_binary_missing(s):
    if not s.get("hydra_ssh_spray_error"):
        return None
    if "hydra binary not installed" not in str(s.get("hydra_ssh_spray_error")):
        return None
    return {
        "name": "Hydra binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('hydra') returned None. Probe could not execute.",
        "remediation": "Install hydra: apt install hydra (Debian/Kali) or build from THC-Hydra source.",
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    # Only emit POSITIVE when probe ran with real input AND found nothing.
    if s.get("hydra_ssh_spray_total"):
        return None
    if s.get("hydra_input_missing"):
        return None
    if s.get("hydra_ssh_port_closed"):
        return None
    if s.get("hydra_ssh_spray_error"):
        return None
    attempts = s.get("hydra_ssh_spray_attempts") or 0
    if not attempts:
        return None
    return {
        "name": "SSH withstood Hydra password spray",
        "severity": "POSITIVE",
        "evidence": (f"{attempts} attempt(s) over "
                     f"{s.get('hydra_ssh_spray_users_tried', 0)} user(s) on port "
                     f"{s.get('hydra_ssh_spray_target_port', 22)} - no valid login."),
        "remediation": ("Keep enforcing strong-password / SSH-key policy. Re-run with a "
                        "bigger wordlist quarterly as breach corpora grow."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


HYDRA_SSH_SPRAY_FINDING_RULES = [
    rule_critical_login,
    rule_input_missing,
    rule_port_closed,
    rule_binary_missing,
    rule_positive,
]
