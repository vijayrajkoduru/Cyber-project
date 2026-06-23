"""js_bridge_audit — findings rules.

Zero-FP: "presence != usage". A JS-bridge marker counted across multidex
classes.dex or a bundled SDK is not the app's exposed surface. Grading uses the
APP-code marker count / file count only; SDK/dex-only references -> INFO.
Severity is scaled by the number of app-code bridge FILES (real exposure
breadth), not raw marker occurrences (which a single class can inflate).
"""


def rule_positive_emit(s):
    if s.get("js_bridge_app_total", 0) > 0:
        return None
    if s.get("js_bridge_audit_total", 0) > 0:
        return None
    return {"name": "No JavascriptInterface usage in DEX",
            "severity": "POSITIVE",
            "cwe": "CWE-749", "owasp": "M3:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, 0 JS-bridge markers",
            "remediation": "No JS↔Java bridges = no attack surface. Maintain."}


def rule_js_bridge_present(s):
    app_files = s.get("js_bridge_app_files", 0)
    if app_files == 0:
        return None
    sev = "HIGH" if app_files >= 3 else "MEDIUM"
    cvss = "7.5" if app_files >= 3 else "5.3"
    hits = s.get("js_bridge_app_hits") or []
    return {"name": f"JavaScript-to-Java bridge usage in {app_files} app class(es)",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-749", "owasp": "M3:2023",
            "evidence": " | ".join(
                f"{h['file']}: {h['marker']} x{h['count']}" for h in hits[:5]
            ),
            "remediation": "Each @JavascriptInterface method is callable from any JS in "
                           "the WebView. (1) Minimize exposed methods. (2) Validate every "
                           "input as untrusted. (3) Don't combine with setAllowFileAccess. "
                           "(4) On API 17+ verify every exposed method has @JavascriptInterface. "
                           "(5) Prefer postMessage / WebMessagePort for new code."}


def rule_js_bridge_sdk_only(s):
    """JS-bridge markers present only in SDK / multidex bytecode."""
    if s.get("js_bridge_app_files", 0) > 0:
        return None
    if s.get("js_bridge_audit_total", 0) == 0:
        return None
    hits = s.get("js_bridge_hits") or []
    return {"name": f"JS-bridge markers present only in libraries/multidex ({s.get('js_bridge_audit_total')})",
            "severity": "INFO",
            "cwe": "CWE-749", "owasp": "M3:2023",
            "evidence": " | ".join(f"{h['file']}: {h['marker']} x{h['count']}" for h in hits[:5]),
            "remediation": "Markers were found in classes.dex / bundled SDKs, not attributable "
                           "to app code. Decompile (jadx) to confirm whether the app exposes its "
                           "own @JavascriptInterface methods before treating as a risk."}


JS_BRIDGE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_js_bridge_present,
    rule_js_bridge_sdk_only,
]
