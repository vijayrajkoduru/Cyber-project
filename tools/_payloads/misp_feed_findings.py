"""misp_feed findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"MISP threat intel feed requires MISP_API_KEY","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add MISP_API_KEY to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"MISP threat intel feed API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
MISP_FEED_FINDING_RULES = [rule_no_key, rule_ok]
