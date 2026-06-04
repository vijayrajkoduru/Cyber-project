"""okta_password_policy_audit - findings rules."""


def rule_library_missing(s):
    if s.get("okta_password_policy_audit_error") != "okta SDK not installed":
        return None
    return {"name": "Okta Python SDK not installed",
            "severity": "INFO",
            "evidence": "ImportError: okta package",
            "remediation": "Install via: pip install okta",
            "cwe": "CWE-1006"}


def rule_input_missing(s):
    if s.get("okta_password_policy_audit_error") != "options.api_token required":
        return None
    return {"name": "Okta API token required",
            "severity": "INFO",
            "evidence": "options.api_token not provided",
            "remediation": ("Generate an API token in Okta Admin Console > Security > API > Tokens "
                            "with okta.policies.read scope. Read-only audit only."),
            "cwe": "CWE-1006"}


def rule_positive(s):
    if s.get("okta_password_policy_audit_total", 0) > 0:
        return None
    if s.get("okta_password_policy_audit_error"):
        return None
    if not s.get("okta_policies"):
        return None
    return {"name": "Okta password + MFA policies meet baseline",
            "severity": "POSITIVE",
            "evidence": (f"{len(s.get('okta_policies') or {})} policy/policies inspected; "
                         f"no weak settings found (min_length>=12, expiry set, lockout sane, "
                         f"MFA enrollment REQUIRED)"),
            "remediation": "Continue quarterly policy review; consider enabling Okta FastPass / WebAuthn.",
            "cwe": "CWE-521", "owasp": "A07:2021"}


def rule_issues(s):
    issues = s.get("okta_policy_issues") or []
    if not issues:
        return None
    summary = "; ".join(f"[{i['policy']}] {i['issue']}" for i in issues[:6])
    return {"name": f"Okta password/MFA policy weaknesses ({len(issues)} issues)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-521", "owasp": "A07:2021",
            "evidence": summary,
            "remediation": ("Strengthen Default Password Policy: min length 14+, complexity required "
                            "(upper+lower+number+symbol), max age 90 days, lockout threshold = 5. "
                            "Set MFA Enrollment Policy > Authenticators > Okta Verify (push + number "
                            "challenge) + WebAuthn = REQUIRED. Disable Voice Call / SMS / Security "
                            "Question factors (per CISA + NIST 800-63B guidance).")}


OKTA_PASSWORD_POLICY_AUDIT_FINDING_RULES = [rule_library_missing, rule_input_missing,
                                              rule_positive, rule_issues]
