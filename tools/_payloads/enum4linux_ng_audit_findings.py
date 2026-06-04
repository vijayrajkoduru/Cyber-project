"""enum4linux_ng_audit - findings rules."""


def rule_positive(s):
    if s.get("enum4linux_ng_audit_total"):
        return None
    if s.get("enum4linux_ng_audit_error"):
        return None
    return {"name": "No null-session enumeration possible",
            "severity": "POSITIVE",
            "evidence": "enum4linux-ng could not extract users/groups/policy without creds",
            "remediation": "Continue blocking null sessions on RestrictAnonymous.",
            "cwe": "CWE-287", "owasp": "A07:2021"}


def rule_null_session(s):
    f = s.get("enum4linux_findings") or []
    if not any(x.get("check") == "null_session_possible" for x in f):
        return None
    return {"name": "Null session accepted on Domain Controller",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-287", "owasp": "A07:2021",
            "evidence": "enum4linux-ng established anonymous SMB session (IPC$ pipe)",
            "remediation": ("Disable null sessions via GPO: Computer Configuration > Policies > "
                            "Windows Settings > Security Settings > Local Policies > Security Options > "
                            "'Network access: Restrict anonymous access to Named Pipes and Shares' = Enabled. "
                            "Also set 'Network access: Do not allow anonymous enumeration of SAM accounts "
                            "and shares' = Enabled. Required on every DC in the forest.")}


def rule_users_leaked(s):
    f = s.get("enum4linux_findings") or []
    user_finding = next((x for x in f if x.get("check") == "users_via_null_session"), None)
    if not user_finding:
        return None
    n = user_finding.get("count", 0)
    sample = user_finding.get("sample", [])
    return {"name": f"{n} domain user accounts leaked via null session",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-200", "owasp": "A01:2021",
            "evidence": f"Sample users: {', '.join(str(x) for x in sample[:8])}",
            "remediation": ("Critical — these accounts can now be targeted with password spray, "
                            "AS-REP roast, kerberoast without first compromising any credentials. "
                            "Block null session (rule above) immediately.")}


def rule_password_policy_leaked(s):
    f = s.get("enum4linux_findings") or []
    if not any(x.get("check") == "password_policy_leaked" for x in f):
        return None
    pp = s.get("enum4linux_password_policy") or {}
    weak = []
    if pp.get("min_length") and isinstance(pp.get("min_length"), (int, str)):
        try:
            if int(str(pp["min_length"])) < 14:
                weak.append(f"min_length={pp['min_length']} (industry standard >=14)")
        except Exception: pass
    if pp.get("lockout_threshold") in (None, 0, "0", "Never"):
        weak.append("no account lockout (password spray unrestricted)")
    if pp.get("complexity") in (False, "Disabled", "No", "0"):
        weak.append("complexity disabled")
    if not weak:
        return None
    return {"name": "Weak domain password policy leaked",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-521", "owasp": "A07:2021",
            "evidence": "Issues: " + "; ".join(weak),
            "remediation": ("Strengthen Default Domain Policy: min length 14+, complexity enabled, "
                            "lockout after 5 attempts within 15 min. Best practice: layer with "
                            "fine-grained password policy (PSO) for privileged accounts >20 chars.")}


ENUM4LINUX_NG_AUDIT_FINDING_RULES = [rule_positive, rule_null_session, rule_users_leaked,
                                       rule_password_policy_leaked]
