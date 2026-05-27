"""mobile_backend_shodan findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Mobile backend Shodan pivot requires SHODAN_API_KEY","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add SHODAN_API_KEY to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Mobile backend Shodan pivot API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
MOBILE_BACKEND_SHODAN_FINDING_RULES = [rule_no_key, rule_ok]
