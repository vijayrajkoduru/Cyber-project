"""netexec_smb_spray - findings rules."""


def rule_binary_missing(s):
    if s.get("netexec_smb_spray_error") != "nxc/netexec binary not installed":
        return None
    return {"name": "NetExec (nxc) binary not installed in scan image",
            "severity": "INFO",
            "evidence": "shutil.which('nxc'/'netexec') returned None",
            "remediation": "Install via: pip install netexec  (or apt install netexec on Kali).",
            "cwe": "CWE-1006"}


def rule_input_missing(s):
    e = s.get("netexec_smb_spray_error") or ""
    if "userlist required" not in e and "password required" not in e:
        return None
    return {"name": "Spray skipped - credentials input required",
            "severity": "INFO",
            "evidence": e,
            "remediation": ("Provide options.userlist (newline-separated usernames, max 100) + "
                            "options.password (single password to spray). Industry-standard "
                            "approach: spray top-10 common passwords (Spring2025!, Welcome1, etc) "
                            "across all enumerated users from previous discovery probe."),
            "cwe": "CWE-1006"}


def rule_positive(s):
    if s.get("netexec_smb_spray_total", 0) > 0:
        return None
    if s.get("netexec_smb_spray_error"):
        return None
    n = s.get("netexec_users_sprayed", 0)
    if n == 0:
        return None
    return {"name": f"Password spray rejected on {n} accounts",
            "severity": "POSITIVE",
            "evidence": f"{n} usernames sprayed against SMB; zero valid logins detected",
            "remediation": "Continue enforcing strong password policy + account lockout.",
            "cwe": "CWE-521", "owasp": "A07:2021"}


def rule_valid_credentials(s):
    creds = s.get("netexec_valid_credentials") or []
    if not creds:
        return None
    sample = ", ".join(f"{c.get('domain', '?')}\\{c.get('user', '?')}" for c in creds[:5])
    return {"name": f"Password spray succeeded - {len(creds)} valid account(s)",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-521", "owasp": "A07:2021",
            "evidence": f"Compromised accounts: {sample}",
            "remediation": ("Force password reset on each compromised account immediately. "
                            "Strengthen password policy: minimum 14 chars, complexity required, "
                            "fine-grained password policies (PSO) for privileged accounts >=20 "
                            "chars. Enable adaptive MFA. Audit for related account compromise "
                            "(same password reuse). Configure Smart Lockout in Entra ID + on-prem "
                            "AD lockout threshold = 5 attempts within 15 min.")}


def rule_lockout_triggered(s):
    if not s.get("netexec_lockout_triggered"):
        return None
    n = s.get("netexec_locked_accounts", 0)
    return {"name": f"Account lockout triggered during spray ({n} accounts)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-307", "owasp": "A07:2021",
            "evidence": f"STATUS_ACCOUNT_LOCKED_OUT returned by {n} attempts",
            "remediation": ("Good: lockout policy is enforced. Caveat: legitimate users now locked. "
                            "Coordinate with customer's helpdesk before next spray attempt. "
                            "Consider longer wait window between spray rounds (lockout typically "
                            "resets after 15-30 min).")}


NETEXEC_SMB_SPRAY_FINDING_RULES = [rule_binary_missing, rule_input_missing,
                                     rule_positive, rule_valid_credentials,
                                     rule_lockout_triggered]
