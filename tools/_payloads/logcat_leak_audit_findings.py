"""logcat_leak_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("logcat_leak_audit_total"):
        return None
    return {"name": "Logcat leak audit: no sensitive Log calls",
            "severity": "POSITIVE",
            "evidence": f"{s.get('log_call_total', 0)} Log.* calls scanned - none reference token/password/auth/etc",
            "remediation": "Strip Log calls from release builds with Proguard: -assumenosideeffects class android.util.Log.",
            "cwe": "CWE-532", "owasp": "M9:2023"}


def rule_suspicious_log_calls(s):
    susp = s.get("suspicious_log_calls") or []
    if not susp:
        return None
    return {"name": f"{len(susp)} Log call(s) likely leak sensitive data to logcat",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-532", "owasp": "M9:2023",
            "evidence": "; ".join(f"{c['file']} ({c['hint']})" for c in susp[:5]),
            "remediation": "Remove Log statements that reference token/password/auth values. Add Proguard rule -assumenosideeffects class android.util.Log { *; } for release builds."}


LOGCAT_LEAK_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_suspicious_log_calls,
]
