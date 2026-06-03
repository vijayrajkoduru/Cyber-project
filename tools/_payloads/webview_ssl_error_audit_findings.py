"""webview_ssl_error_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("webview_ssl_error_audit_total"):
        return None
    return {"name": "No WebView TLS-bypass via handler.proceed()",
            "severity": "POSITIVE",
            "evidence": (f"{s.get('files_scanned', 0)} files scanned | "
                         f"cancel() overrides={s.get('cancel_overrides', 0)} "
                         f"WebView users={len(s.get('webview_users') or [])}"),
            "remediation": "Continue letting onReceivedSslError fall through to cancel() / no override.",
            "cwe": "CWE-295", "owasp": "M3:2023"}


def rule_proceed_override(s):
    pr = s.get("proceed_overrides") or []
    if not pr:
        return None
    return {"name": f"WebView onReceivedSslError -> handler.proceed() in {len(pr)} class(es)",
            "severity": "CRITICAL", "cvss": "9.0",
            "cwe": "CWE-295", "owasp": "M3:2023",
            "evidence": "Files: " + ", ".join(pr[:6]),
            "remediation": ("Remove every handler.proceed() in onReceivedSslError. Default behaviour "
                            "(no override -> cancel) is correct. Accepting bad certs in WebView = full "
                            "MITM on any page the user navigates to inside the app.")}


WEBVIEW_SSL_ERROR_AUDIT_FINDING_RULES = [rule_positive_emit, rule_proceed_override]
