"""addjavascriptinterface_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("addjavascriptinterface_audit_total"):
        return None
    return {"name": "WebView JS bridge posture clean or absent",
            "severity": "POSITIVE",
            "evidence": (f"bridge users={len(s.get('bridge_users') or [])} "
                         f"@JavascriptInterface={len(s.get('annotated_files') or [])} "
                         f"targetSdk={s.get('target_sdk')}"),
            "remediation": "Continue annotating each exposed method with @JavascriptInterface and keep targetSdk >= 17.",
            "cwe": "CWE-749", "owasp": "M4:2023"}


def rule_pre_api17(s):
    if not (s.get("bridge_users") and s.get("target_sdk") and s.get("target_sdk") < 17):
        return None
    return {"name": f"WebView JS bridge on targetSdk {s['target_sdk']} (<17) - Reflection RCE class",
            "severity": "CRITICAL", "cvss": "9.5",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": f"Files: {', '.join((s.get('bridge_users') or [])[:6])}",
            "remediation": "Raise targetSdkVersion to >=17. Pre-17 every exposed object method is Reflection-reachable from any loaded page."}


def rule_dangerous_methods(s):
    d = s.get("dangerous_method_co") or []
    if not d: return None
    return {"name": f"WebView JS bridge co-located with Runtime / File / ProcessBuilder in {len(d)} class(es)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(d[:6]),
            "remediation": "Audit each exposed method. Never expose Runtime.exec / file I/O / package introspection to JS."}


def rule_unannotated(s):
    if s.get("dangerous_method_co"): return None
    if not s.get("bridge_users") or s.get("annotated_files"): return None
    return {"name": "addJavascriptInterface called without @JavascriptInterface annotations",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": f"Bridge callers: {', '.join((s.get('bridge_users') or [])[:6])}",
            "remediation": "Mark each exposed method @JavascriptInterface; otherwise JS sees ALL public methods of the object."}


ADDJAVASCRIPTINTERFACE_AUDIT_FINDING_RULES = [rule_positive_emit, rule_pre_api17, rule_dangerous_methods, rule_unannotated]
