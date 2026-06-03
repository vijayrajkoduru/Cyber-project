"""webview_mixed_content_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("webview_mixed_content_audit_total"):
        return None
    return {"name": "WebView mixed-content policy strict",
            "severity": "POSITIVE",
            "evidence": (f"NEVER={s.get('never_allow_callers', 0)} "
                         f"COMPAT={s.get('compatibility_callers', 0)} "
                         f"ALWAYS=0 | WebView users={len(s.get('webview_users') or [])}"),
            "remediation": "Continue defaulting to MIXED_CONTENT_NEVER_ALLOW on every WebView.",
            "cwe": "CWE-319", "owasp": "M3:2023"}


def rule_always_allow(s):
    a = s.get("always_allow_callers") or []
    if not a:
        return None
    return {"name": f"WebView setMixedContentMode(ALWAYS_ALLOW) in {len(a)} class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-319", "owasp": "M3:2023",
            "evidence": "Files: " + ", ".join(a[:6]),
            "remediation": ("Replace with setMixedContentMode(MIXED_CONTENT_NEVER_ALLOW). "
                            "ALWAYS_ALLOW lets HTTPS pages pull HTTP scripts - MITM gets script-injection "
                            "into your auth pages.")}


WEBVIEW_MIXED_CONTENT_AUDIT_FINDING_RULES = [rule_positive_emit, rule_always_allow]
