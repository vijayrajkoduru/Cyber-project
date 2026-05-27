"""http_method_enum findings."""

def rule_dangerous(s):
    d = s.get("am_dangerous") or []
    if not d: return None
    return {"name":f"Dangerous HTTP methods enabled: {', '.join(d)}","severity":"MEDIUM","cvss":"5.3",
            "cwe":"CWE-749","owasp":"M5:2023",
            "evidence":f"Allowed: {', '.join(s.get('allowed_methods',[]))}",
            "remediation":"Disable TRACE/CONNECT. Restrict PUT/DELETE to authenticated API routes only."}
def rule_safe(s):
    if (s.get("am_dangerous") or []): return None
    if (s.get("am_count") or 0) == 0: return None
    return {"name":"Only safe HTTP methods allowed","severity":"POSITIVE",
            "evidence":f"Allowed: {', '.join(s.get('allowed_methods',[]))}",
            "remediation":"Maintain.",
            "cwe":"CWE-749","owasp":"M5:2023"}
HTTP_METHOD_ENUM_FINDING_RULES = [rule_dangerous, rule_safe,
    rule_positive_emit,
]

def rule_positive_emit(s):
    """POSITIVE-emit when no risk indicators present (VL-FORGE pattern)."""
    if s.get("dangerous_methods") or s.get("method_unsafe_count"):
        return None
    return {
        "name": "No dangerous HTTP methods enabled",
        "severity": "POSITIVE",
        "evidence": "OPTIONS returned safe set (GET/HEAD/POST) - no TRACE/PUT/DELETE/CONNECT",
        "remediation": "Maintain - dangerous methods (TRACE/PUT/DELETE) disabled.",
        "cwe": "CWE-200", "owasp": "N/A"
    }
