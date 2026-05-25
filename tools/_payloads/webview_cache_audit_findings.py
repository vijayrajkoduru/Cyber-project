"""webview_cache_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("webview_cache_audit_total"):
        return None
    return {"name": "WebView cache configuration: clean",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no risky WebView API hits",
            "remediation": "Continue using safe defaults. Avoid setAllowFileAccess(true) and the deprecated AppCache.",
            "cwe": "CWE-200", "owasp": "M7:2023"}


def rule_risky_webview_apis(s):
    risks = s.get("webview_risks") or {}
    if not risks:
        return None
    flat = "; ".join(f"{k} in {len(v)} file(s)" for k, v in list(risks.items())[:5])
    sev = "HIGH" if any(k in risks for k in ("setSavePassword", "setAllowUniversalAccessFromFileURLs",
                                              "setAllowFileAccessFromFileURLs")) else "MEDIUM"
    return {"name": f"{len(risks)} risky WebView API(s) used",
            "severity": sev, "cvss": "6.5" if sev == "HIGH" else "5.0",
            "cwe": "CWE-200", "owasp": "M7:2023",
            "evidence": flat,
            "remediation": "Remove setSavePassword / setSaveFormData (deprecated, leak PII). Set setAllowFileAccess(false) unless required. setMixedContentMode(MIXED_CONTENT_NEVER_ALLOW) for HTTPS-only WebViews."}


def rule_no_clear_cache(s):
    if s.get("webview_has_clear_cache") or not s.get("webview_users"):
        return None
    return {"name": "WebView used but no clearCache() call found",
            "severity": "LOW", "cvss": "3.0",
            "cwe": "CWE-525", "owasp": "M9:2023",
            "evidence": f"WebView callers: {len(s.get('webview_users', []))}",
            "remediation": "Call webView.clearCache(true) on logout to prevent cached PII / session-cookie reuse."}


WEBVIEW_CACHE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_risky_webview_apis,
    rule_no_clear_cache,
]
