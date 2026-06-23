"""logcat_leak_audit — findings rules.

Zero-FP: a sensitively-*named* variable in a Log call is not proof a secret is
leaked. Only Log calls whose argument carries a real secret/PII VALUE are
graded HIGH; name-only matches are reported at INFO.
"""


def rule_positive_emit(s):
    if s.get("logcat_leak_audit_total") or s.get("hint_log_calls"):
        return None
    return {"name": "Logcat leak audit: no sensitive Log calls",
            "severity": "POSITIVE",
            "evidence": f"{s.get('log_call_total', 0)} app-code Log.* calls scanned - no secret/PII values logged",
            "remediation": "Strip Log calls from release builds with Proguard: -assumenosideeffects class android.util.Log.",
            "cwe": "CWE-532", "owasp": "M9:2023"}


def rule_confirmed_log_calls(s):
    conf = s.get("confirmed_log_calls") or []
    if not conf:
        return None
    return {"name": f"{len(conf)} Log call(s) leak a secret/PII value to logcat",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-532", "owasp": "M9:2023",
            "evidence": "; ".join(f"{c['file']} ({c['hint']})" for c in conf[:5]),
            "remediation": "Remove Log statements that emit token/key/PII values. Add Proguard rule -assumenosideeffects class android.util.Log { *; } for release builds."}


def rule_hint_log_calls(s):
    # Only fire if there are name-only hints AND no confirmed leaks.
    hints = s.get("hint_log_calls") or []
    if not hints or s.get("confirmed_log_calls"):
        return None
    return {"name": f"{len(hints)} Log call(s) reference sensitively-named fields (no value confirmed)",
            "severity": "INFO",
            "cwe": "CWE-532", "owasp": "M9:2023",
            "evidence": "; ".join(f"{c['file']} ({c['hint']})" for c in hints[:5]),
            "remediation": "Manually confirm whether these Log calls emit the actual secret value. A sensitively-named variable is not proof of a leak. Strip Log calls from release builds regardless."}


LOGCAT_LEAK_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_confirmed_log_calls,
    rule_hint_log_calls,
]
