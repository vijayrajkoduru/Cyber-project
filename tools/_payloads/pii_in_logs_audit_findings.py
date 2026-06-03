"""pii_in_logs_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("pii_in_logs_audit_total"):
        return None
    return {"name": "No PII near log calls + no hardcoded emails",
            "severity": "POSITIVE",
            "evidence": f"Log callers={s.get('log_users', 0)} / {s.get('files_scanned', 0)} files",
            "remediation": "Continue routing logs through a PII-redacting wrapper; strip release-build logs via ProGuard.",
            "cwe": "CWE-532", "owasp": "M9:2023"}


def rule_pii_near_logs(s):
    p = s.get("pii_in_log_files") or []
    if not p: return None
    return {"name": f"PII identifiers near log calls in {len(p)} class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-532", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(p[:6]),
            "remediation": "Wrap Log.d / NSLog through a redacting helper. Strip logs in release builds via -assumenosideeffects (ProGuard) or DEBUG flag guards."}


def rule_email_literals(s):
    e = s.get("email_literals_found") or []
    if not e: return None
    return {"name": f"{len(e)} email literal(s) hardcoded in binary",
            "severity": "LOW", "cvss": "3.1",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": "Found: " + ", ".join(e[:5]),
            "remediation": "Move support / admin emails to backend config; hardcoded emails are phishing target lists."}


PII_IN_LOGS_AUDIT_FINDING_RULES = [rule_positive_emit, rule_pii_near_logs, rule_email_literals]
