"""osint_industries findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"OSINT Industries requires API key","severity":"INFO",
            "evidence":"Configure env var on backend container","remediation":"Set the relevant API key in docker-compose env to enable this scanner.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    c = s.get("count", 0)
    return {"name":f"OSINT Industries: {c} result(s)","severity":"POSITIVE" if c==0 else "INFO",
            "evidence":s.get("sample",""),"remediation":"Audit results for over-exposure.",
            "cwe":"CWE-200","owasp":"M2:2023"}
OSINT_INDUSTRIES_FINDING_RULES = [rule_no_key, rule_ok]
