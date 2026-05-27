"""intelligence_x_search findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Intelligence X search requires INTELX_API_KEY","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add INTELX_API_KEY to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Intelligence X search API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
INTELLIGENCE_X_SEARCH_FINDING_RULES = [rule_no_key, rule_ok]
