"""http_method_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("http_method_audit_total"):
        return None
    counts = s.get("http_method_counts") or {}
    return {"name": "HTTP methods used: standard set only (GET / POST / PUT / DELETE / PATCH)",
            "severity": "POSITIVE",
            "evidence": "Counts: " + ", ".join(f"{m}: {c}" for m, c in counts.items() if c) if counts else f"{s.get('files_scanned', 0)} files scanned",
            "remediation": "Standard methods scoped. Burp testing can focus on each endpoint per method.",
            "cwe": "CWE-200", "owasp": "M3:2023"}


def rule_interesting_methods(s):
    interesting = s.get("interesting_methods") or {}
    if not interesting:
        return None
    return {"name": f"Unusual HTTP method(s) detected: {', '.join(interesting.keys())}",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M3:2023",
            "evidence": "Counts: " + ", ".join(f"{m}: {c}" for m, c in interesting.items()),
            "remediation": "TRACE/CONNECT/PROPFIND on production endpoints can be info-disclosure (TRACE = XST), tunneling (CONNECT), or webdav (PROPFIND). Verify with Burp Repeater on each endpoint."}


def rule_method_override(s):
    files = s.get("method_override_headers") or []
    if not files:
        return None
    return {"name": "X-HTTP-Method-Override header used",
            "severity": "MEDIUM", "cvss": "4.5",
            "cwe": "CWE-693", "owasp": "M3:2023",
            "evidence": "Files: " + ", ".join(files[:5]),
            "remediation": "Method-Override headers let a POST tunnel as DELETE / PUT — bypasses naive WAFs and CSRF defenses tied to method. Verify server rejects the override OR ensure CSRF tokens cover all methods."}


HTTP_METHOD_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_interesting_methods,
    rule_method_override,
]
