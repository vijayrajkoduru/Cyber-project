"""file_scheme_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("file_scheme_audit_total"):
        return None
    return {"name": "WebView file:// posture clean",
            "severity": "POSITIVE",
            "evidence": f"WebView users={s.get('webview_users', 0)} - no allowFileAccess / allowUniversalAccessFromFileURLs",
            "remediation": "Continue defaulting to setAllowFileAccess(false).",
            "cwe": "CWE-749", "owasp": "M4:2023"}


def rule_universal_access(s):
    af = s.get("allow_from_file_urls") or []
    if not af: return None
    return {"name": f"WebView setAllowUniversalAccessFromFileURLs(true) in {len(af)} class(es)",
            "severity": "CRITICAL", "cvss": "9.0",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(af[:6]),
            "remediation": "Always pass false. UXSS class - a file:// page can read any other origin."}


def rule_allow_file(s):
    af = s.get("allow_file_access") or []
    if not af: return None
    return {"name": f"WebView setAllowFileAccess(true) in {len(af)} class(es)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(af[:6]),
            "remediation": "Default to false. Only enable if you genuinely need local file load + you trust the URI source."}


FILE_SCHEME_AUDIT_FINDING_RULES = [rule_positive_emit, rule_universal_access, rule_allow_file]
