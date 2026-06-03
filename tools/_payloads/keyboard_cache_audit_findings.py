"""keyboard_cache_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("keyboard_cache_audit_total"):
        return None
    return {"name": "Keyboard cache controls present on sensitive fields",
            "severity": "POSITIVE",
            "evidence": (f"Android sensitive={len(s.get('android_sensitive_fields') or [])} "
                         f"iOS sensitive={len(s.get('ios_sensitive_files') or [])} - "
                         "all protected or none present"),
            "remediation": "Continue using inputType=textPassword / textNoSuggestions and isSecureTextEntry.",
            "cwe": "CWE-524", "owasp": "M9:2023"}


def rule_android_unprotected(s):
    n = s.get("android_unprotected") or 0
    if not n:
        return None
    return {"name": f"Android: {n} sensitive EditText(s) miss inputType protection",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-524", "owasp": "M9:2023",
            "evidence": (f"Sensitive hints found in {len(s.get('android_sensitive_fields') or [])} layout(s); "
                         f"only ~{(s.get('android_sensitive_fields') and len(s['android_sensitive_fields']) - n) or 0} use textPassword/textNoSuggestions"),
            "remediation": ("Add android:inputType=\"textPassword\" or "
                            "android:inputType=\"textNoSuggestions\" on every sensitive EditText.")}


def rule_ios_unprotected(s):
    n = s.get("ios_unprotected") or 0
    if not n:
        return None
    return {"name": f"iOS: {n} sensitive UITextField(s) miss isSecureTextEntry / autocorrectionType=.no",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-524", "owasp": "M9:2023",
            "evidence": f"Sensitive UITextField sources: {', '.join((s.get('ios_sensitive_files') or [])[:6])}",
            "remediation": ("Set isSecureTextEntry=true and autocorrectionType=.no on password / PIN / CVV fields "
                            "to block iOS keyboard learning + autocorrect dictionary.")}


KEYBOARD_CACHE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_android_unprotected,
    rule_ios_unprotected,
]
