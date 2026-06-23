"""file_scheme_audit - findings rules.

Zero-FP: "presence != usage". File-access setters inside bundled SDKs are not
the app's WebView config. setAllowFileAccess(true) is only a real concern when
the app also loads a file:// URL; otherwise it's an unused setter (and was the
historical platform default) -> INFO.
"""


def rule_positive_emit(s):
    if s.get("file_scheme_audit_total"):
        return None
    return {"name": "WebView file:// posture clean",
            "severity": "POSITIVE",
            "evidence": f"WebView users={s.get('webview_users', 0)} - no app-code allowFileAccess+file:// load / universal file access",
            "remediation": "Continue defaulting to setAllowFileAccess(false).",
            "cwe": "CWE-749", "owasp": "M4:2023"}


def rule_universal_access(s):
    af = s.get("app_allow_from_file_urls") or []
    if not af: return None
    return {"name": f"WebView setAllowUniversalAccessFromFileURLs(true) in {len(af)} app class(es)",
            "severity": "CRITICAL", "cvss": "9.0",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(af[:6]),
            "remediation": "Always pass false. UXSS class - a file:// page can read any other origin."}


def rule_allow_file(s):
    af = s.get("app_allow_file_access") or []
    loaders = s.get("app_file_url_loaders") or []
    if not af or not loaders: return None
    return {"name": f"WebView setAllowFileAccess(true) + file:// load in {len(af)} app class(es)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": "Setters: " + ", ".join(af[:4]) + " | file:// loaders: " + ", ".join(loaders[:4]),
            "remediation": "Default to false. Only enable if you genuinely need local file load + you trust the URI source."}


def rule_allow_file_unused(s):
    """setAllowFileAccess(true) present but no file:// load observed (or SDK-only)."""
    app_af = s.get("app_allow_file_access") or []
    all_af = s.get("allow_file_access") or []
    loaders = s.get("app_file_url_loaders") or []
    if s.get("app_allow_from_file_urls"):
        return None
    if app_af and loaders:  # graded by rule_allow_file already
        return None
    if not all_af:
        return None
    if app_af:
        detail = "no file:// URL load observed"
        files = app_af
    else:
        detail = "only in bundled SDK/library code"
        files = all_af
    return {"name": f"WebView setAllowFileAccess(true) present — {detail} ({len(files)} class(es))",
            "severity": "INFO",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(files[:6]),
            "remediation": "setAllowFileAccess defaulted to true on older WebView; without a file:// load it is low-risk. Set it false explicitly and confirm no file:// content is rendered."}


FILE_SCHEME_AUDIT_FINDING_RULES = [rule_positive_emit, rule_universal_access, rule_allow_file, rule_allow_file_unused]
