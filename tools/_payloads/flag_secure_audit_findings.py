"""flag_secure_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("flag_secure_audit_total"):
        return None
    users = s.get("flag_secure_users") or []
    if users:
        return {"name": f"FLAG_SECURE applied to {len(users)} Activity(ies)",
                "severity": "POSITIVE",
                "evidence": "Sensitive screens explicitly block screenshots / screen-recording",
                "remediation": "Continue applying FLAG_SECURE to all login / payment / PIN entry screens.",
                "cwe": "CWE-200", "owasp": "M9:2023"}
    return {"name": "No sensitive Activities detected (or all clean)",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
            "remediation": "If you ever add a login / payment screen, set window.FLAG_SECURE on it.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_unsafe_sensitive_activities(s):
    unsafe = s.get("unsafe_activities") or []
    if not unsafe:
        return None
    return {"name": f"{len(unsafe)} sensitive Activity(ies) missing FLAG_SECURE",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(a["file"] for a in unsafe[:5]),
            "remediation": "Add getWindow().setFlags(FLAG_SECURE, FLAG_SECURE) in onCreate(). Prevents Android app-switcher thumbnail leak + screen-recording malware capture."}


FLAG_SECURE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_unsafe_sensitive_activities,
]
