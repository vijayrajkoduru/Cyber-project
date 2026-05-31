"""js_bridge_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("js_bridge_audit_total", 0)
    if n > 0: return None
    return {"name": "No JavascriptInterface usage in DEX",
            "severity": "POSITIVE",
            "cwe": "CWE-749", "owasp": "M3:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, 0 JS-bridge markers",
            "remediation": "No JS↔Java bridges = no attack surface. Maintain."}


def rule_js_bridge_present(s):
    n = s.get("js_bridge_audit_total", 0)
    if n == 0: return None
    sev = "HIGH" if n >= 5 else "MEDIUM"
    cvss = "7.5" if n >= 5 else "5.3"
    hits = s.get("js_bridge_hits") or []
    return {"name": f"JavaScript-to-Java bridge usage ({n} marker(s))",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-749", "owasp": "M3:2023",
            "evidence": " | ".join(
                f"{h['file']}: {h['marker']} x{h['count']}" for h in hits[:5]
            ),
            "remediation": "Each @JavascriptInterface method is callable from any "
                           "JS in the WebView. (1) Minimize: only expose what's "
                           "absolutely needed. (2) Validate every input as untrusted. "
                           "(3) Don't combine with setAllowFileAccess. (4) On API 17+, "
                           "@JavascriptInterface annotation IS the protection — verify "
                           "every exposed method has it. (5) Prefer postMessage / "
                           "WebMessagePort over JS interface for new code."}


JS_BRIDGE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_js_bridge_present,
]
