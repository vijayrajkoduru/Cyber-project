"""webview_config_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("webview_config_audit_total", 0)
    if n > 0: return None
    return {"name": "No risky WebView configuration detected",
            "severity": "POSITIVE",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files",
            "remediation": "Maintain WebView secure-defaults (no setAllow*FromFileURLs, "
                           "no setAllowFileAccess unless required)."}


def rule_universal_file_access(s):
    hits = s.get("webview_risky_setters") or []
    critical = [h for h in hits if h["severity"] == "critical"]
    if not critical: return None
    return {"name": "CRITICAL WebView: universal file:// access enabled",
            "severity": "CRITICAL", "cvss": "9.1",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": ", ".join(h["setter"] for h in critical[:3]),
            "remediation": "REMOVE setAllowUniversalAccessFromFileURLs(true). "
                           "It allows file:// URLs to read ANY origin including "
                           "http:// — single XSS = full filesystem read on device. "
                           "If you need cross-origin file access, redesign the flow "
                           "using a content provider or restricted custom scheme."}


def rule_high_severity_setters(s):
    hits = s.get("webview_risky_setters") or []
    high = [h for h in hits if h["severity"] == "high"]
    if not high: return None
    return {"name": f"{len(high)} HIGH-severity WebView setter(s) detected",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": ", ".join(f"{h['setter']} ({h['desc']})" for h in high[:5]),
            "remediation": "Audit each setter's actual call site (decompile via "
                           "jadx). Disable setAllowFileAccess unless your app "
                           "actively renders local PDF/HTML. Disable mixed content."}


def rule_js_enabled(s):
    hits = s.get("webview_risky_setters") or []
    js = [h for h in hits if h["setter"] == "setJavaScriptEnabled"]
    if not js: return None
    return {"name": "WebView has JavaScript enabled (setJavaScriptEnabled)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-829", "owasp": "M3:2023",
            "evidence": f"found in {len(js)} location(s)",
            "remediation": "Required for SPA WebViews — confirm only loading "
                           "your own HTML / HTTPS sources. NEVER mix with "
                           "@JavascriptInterface unless interface methods are "
                           "API-26+ @JavascriptInterface restricted."}
