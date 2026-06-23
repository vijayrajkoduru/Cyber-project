"""addjavascriptinterface_audit - findings rules.

Zero-FP: "presence != usage". A JS bridge inside a bundled SDK is not the app's
exposed surface. Grading uses APP-code subsets only:
- pre-API-17 RCE: app exposes a bridge AND targetSdk < 17.
- dangerous methods: an exposed (@JavascriptInterface) app bridge co-located
  with Runtime/File/ProcessBuilder.
- unannotated bridge: app calls addJavascriptInterface with no annotations.
Bridges seen only in SDK/library code are reported at INFO.
"""


def rule_positive_emit(s):
    if s.get("addjavascriptinterface_audit_total"):
        return None
    return {"name": "WebView JS bridge posture clean or absent",
            "severity": "POSITIVE",
            "evidence": (f"app bridge users={len(s.get('app_bridge_users') or [])} "
                         f"app @JavascriptInterface={len(s.get('app_annotated_files') or [])} "
                         f"targetSdk={s.get('target_sdk')}"),
            "remediation": "Continue annotating each exposed method with @JavascriptInterface and keep targetSdk >= 17.",
            "cwe": "CWE-749", "owasp": "M4:2023"}


def rule_pre_api17(s):
    if not (s.get("app_bridge_users") and s.get("target_sdk") and s.get("target_sdk") < 17):
        return None
    return {"name": f"WebView JS bridge on targetSdk {s['target_sdk']} (<17) - Reflection RCE class",
            "severity": "CRITICAL", "cvss": "9.5",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": f"App files: {', '.join((s.get('app_bridge_users') or [])[:6])}",
            "remediation": "Raise targetSdkVersion to >=17. Pre-17 every exposed object method is Reflection-reachable from any loaded page."}


def rule_dangerous_methods(s):
    d = s.get("dangerous_method_co") or []
    if not d: return None
    return {"name": f"Exposed WebView JS bridge co-located with Runtime / File / ProcessBuilder in {len(d)} app class(es)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(d[:6]),
            "remediation": "Audit each exposed method. Never expose Runtime.exec / file I/O / package introspection to JS."}


def rule_unannotated(s):
    if s.get("dangerous_method_co"): return None
    if not s.get("app_bridge_users") or s.get("app_annotated_files"): return None
    return {"name": "addJavascriptInterface called without @JavascriptInterface annotations (app code)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": f"Bridge callers: {', '.join((s.get('app_bridge_users') or [])[:6])}",
            "remediation": "Mark each exposed method @JavascriptInterface; otherwise JS sees ALL public methods of the object."}


def rule_sdk_bridge_only(s):
    """addJavascriptInterface present only in bundled SDK/library code."""
    all_users = s.get("bridge_users") or []
    app_users = s.get("app_bridge_users") or []
    if not all_users or app_users:
        return None
    return {"name": f"WebView JS bridge present only in bundled libraries ({len(all_users)} file(s))",
            "severity": "INFO",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": "Library files: " + ", ".join(all_users[:6]),
            "remediation": "The JS bridge lives in a 3rd-party SDK, not the app's own code. Confirm the SDK exposes only safe, annotated methods; no app action otherwise."}


ADDJAVASCRIPTINTERFACE_AUDIT_FINDING_RULES = [rule_positive_emit, rule_pre_api17, rule_dangerous_methods, rule_unannotated, rule_sdk_bridge_only]
