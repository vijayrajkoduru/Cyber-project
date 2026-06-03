"""permission_overask_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("permission_overask_audit_total"):
        return None
    return {"name": "Declared permissions all used in code",
            "severity": "POSITIVE",
            "evidence": f"Declared={len(s.get('declared_permissions') or [])}",
            "remediation": "Continue declaring only what you use; remove unused entries on every release.",
            "cwe": "CWE-250", "owasp": "M9:2023"}


def rule_overask(s):
    oa = s.get("overasked_permissions") or []
    if not oa: return None
    return {"name": f"{len(oa)} permission(s) declared but never invoked in code",
            "severity": "MEDIUM", "cvss": "4.0",
            "cwe": "CWE-250", "owasp": "M9:2023",
            "evidence": "Permissions: " + ", ".join(oa[:8]),
            "remediation": "Remove unused <uses-permission> entries. Play Store + Apple App Review penalize unjustified permission requests."}


PERMISSION_OVERASK_AUDIT_FINDING_RULES = [rule_positive_emit, rule_overask]
