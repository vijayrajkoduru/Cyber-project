"""hibp_breach_check findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"HIBP breach check requires HIBP_API_KEY","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add HIBP_API_KEY to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"HIBP breach check API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
HIBP_BREACH_CHECK_FINDING_RULES = [rule_no_key, rule_ok]
