"""webview_config_audit — findings rules.

Zero-FP: "presence != usage". A setter byte-string appearing in a multidex
classes.dex (or a bundled SDK) does not mean the APP enabled it. Only setters
that are (a) in app-code smali and (b) actually set to TRUE are graded; every
other reference is reported at INFO for manual confirmation.
"""


def _graded(s):
    return s.get("webview_graded_setters") or []


def rule_positive_emit(s):
    if s.get("webview_config_audit_total", 0) > 0:
        return None
    if s.get("webview_risky_setters"):
        return None
    return {"name": "No risky WebView configuration detected",
            "severity": "POSITIVE",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files",
            "remediation": "Maintain WebView secure-defaults (no setAllow*FromFileURLs, "
                           "no setAllowFileAccess unless required)."}


def rule_universal_file_access(s):
    critical = [h for h in _graded(s) if h["severity"] == "critical"]
    if not critical: return None
    return {"name": "CRITICAL WebView: universal file:// access enabled (app code)",
            "severity": "CRITICAL", "cvss": "9.1",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": ", ".join(h["setter"] for h in critical[:3]),
            "remediation": "REMOVE setAllowUniversalAccessFromFileURLs(true). "
                           "It allows file:// URLs to read ANY origin including "
                           "http:// — single XSS = full filesystem read on device."}


def rule_high_severity_setters(s):
    high = [h for h in _graded(s) if h["severity"] == "high"]
    if not high: return None
    return {"name": f"{len(high)} HIGH-severity WebView setter(s) enabled in app code",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": ", ".join(f"{h['setter']} ({h['desc']})" for h in high[:5]),
            "remediation": "Disable setAllowFileAccess unless your app actively renders "
                           "local PDF/HTML. Disable mixed content."}


def rule_js_enabled(s):
    js = [h for h in _graded(s) if h["setter"] == "setJavaScriptEnabled"]
    if not js: return None
    return {"name": "WebView has JavaScript enabled (setJavaScriptEnabled, app code)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": f"found in {len(js)} app location(s)",
            "remediation": "Required for SPA WebViews — confirm only loading your own "
                           "HTML / HTTPS sources. NEVER mix with @JavascriptInterface "
                           "unless interface methods are properly restricted."}


def rule_unconfirmed_setters(s):
    """Setter references present only in classes.dex / SDK code, or not confirmed
    set to TRUE. Reported for awareness, not graded."""
    all_hits = s.get("webview_risky_setters") or []
    graded = _graded(s)
    if not all_hits or graded:
        return None
    seen = sorted({h["setter"] for h in all_hits})
    return {"name": f"WebView setter references present but not confirmed enabled in app code ({len(all_hits)})",
            "severity": "INFO",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": "Setters: " + ", ".join(seen[:8]),
            "remediation": "These setters appear in multidex/SDK bytecode or are not set to true. "
                           "Decompile (jadx) and confirm the app actually enables them before treating as a risk."}


WEBVIEW_CONFIG_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_universal_file_access,
    rule_high_severity_setters,
    rule_js_enabled,
    rule_unconfirmed_setters,
]
