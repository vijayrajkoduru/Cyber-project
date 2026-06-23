"""clipboard_api_audit — findings rules.

Zero-FP: "presence != usage". A class merely referencing ClipboardManager (or
just having a sensitive name) is not a leak. The graded MEDIUM finding requires
an actual clipboard WRITE inside a sensitively-named class. Everything else is
reported at INFO.
"""


def rule_positive_emit(s):
    if s.get("clipboard_api_audit_total") or s.get("clipboard_write_files"):
        return None
    return {"name": "Clipboard API: no sensitive-context usage detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned — no app-code clipboard writes in sensitive classes",
            "remediation": "If you ever copy a one-time code or password, clear the clipboard after a few seconds.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_sensitive_clipboard_use(s):
    sens = s.get("sensitive_clipboard_files") or []
    if not sens:
        return None
    return {"name": f"Clipboard WRITE in {len(sens)} sensitive class(es)",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "Writers: " + ", ".join(sens[:5]),
            "remediation": "Avoid writing OTP / password / token to clipboard. If unavoidable, schedule ClipboardManager.clearPrimaryClip() after 30s or use ClipDescription.EXTRA_IS_SENSITIVE on Android 13+."}


def rule_clipboard_general(s):
    writes = s.get("clipboard_write_files") or []
    if not writes or s.get("sensitive_clipboard_files"):
        return None
    return {"name": f"Clipboard WRITE by {len(writes)} class(es) (non-sensitive name)",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "Writers: " + ", ".join(writes[:5]),
            "remediation": "Review each write. On Android 13+ flag sensitive content with ClipDescription.EXTRA_IS_SENSITIVE."}


CLIPBOARD_API_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_sensitive_clipboard_use,
    rule_clipboard_general,
]
