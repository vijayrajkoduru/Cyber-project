"""clipboard_api_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("clipboard_api_audit_total"):
        return None
    return {"name": "Clipboard API: no sensitive-context usage detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
            "remediation": "If you ever copy a one-time code or password, clear the clipboard after a few seconds.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_sensitive_clipboard_use(s):
    sens = s.get("sensitive_clipboard_files") or []
    if not sens:
        return None
    return {"name": f"Clipboard API used in {len(sens)} sensitive class(es)",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "Callers: " + ", ".join(sens[:5]),
            "remediation": "Avoid writing OTP / password / token to clipboard. If unavoidable, schedule ClipboardManager.clearPrimaryClip() after 30s or use ClipDescription.EXTRA_IS_SENSITIVE on Android 13+."}


def rule_clipboard_general(s):
    cb = s.get("clipboard_files") or []
    if not cb or s.get("sensitive_clipboard_files"):
        return None
    return {"name": f"Clipboard API used by {len(cb)} class(es)",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "Callers: " + ", ".join(cb[:5]),
            "remediation": "Review each usage. On Android 13+ flag sensitive content with ClipDescription.EXTRA_IS_SENSITIVE."}


CLIPBOARD_API_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_sensitive_clipboard_use,
    rule_clipboard_general,
]
