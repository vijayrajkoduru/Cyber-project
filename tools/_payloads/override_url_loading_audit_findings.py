"""override_url_loading_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("override_url_loading_audit_total"):
        return None
    return {"name": "WebView URL-loading override allowlisted or absent",
            "severity": "POSITIVE",
            "evidence": f"Allowlisted overrides={s.get('allowlisted_overrides', 0)} | WebView users={s.get('webview_users', 0)}",
            "remediation": "Continue allowlisting host (.equals / .endsWith) before returning true.",
            "cwe": "CWE-601", "owasp": "M4:2023"}


def rule_blind_override(s):
    bo = s.get("blind_overrides") or []
    if not bo: return None
    return {"name": f"WebView shouldOverrideUrlLoading returns true without host check in {len(bo)} class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-601", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(bo[:6]),
            "remediation": "Verify URL host is in your allowlist before keeping the load inside the WebView. Otherwise an attacker can load a phishing page rendered as if it were your app."}


OVERRIDE_URL_LOADING_AUDIT_FINDING_RULES = [rule_positive_emit, rule_blind_override]
