"""leakcheck_search findings."""

def rule_f(s):
    if s.get("needs_api_key"): return None
    c = s.get("leak_count") or 0
    if c == 0: return None
    return {"name":f"LeakCheck: {c} breach record(s) for domain","severity":"HIGH","cvss":"7.5",
            "cwe":"CWE-200","owasp":"M9:2023",
            "evidence":f"{c} records in breach databases",
            "remediation":"Notify affected users + force password reset. Implement HIBP integration for proactive monitoring."}
def rule_no_key(s):
    if not s.get("needs_api_key"): return None
    return {"name":"LeakCheck requires LEAKCHECK_API_KEY","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add LEAKCHECK_API_KEY.",
            "cwe":"CWE-200","owasp":"M9:2023"}
LEAKCHECK_SEARCH_FINDING_RULES = [rule_f, rule_no_key]
