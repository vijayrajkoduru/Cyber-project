"""ghunt_google_audit findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"GHunt Google account audit requires GHUNT_COOKIE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add GHUNT_COOKIE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"GHunt Google account audit API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
GHUNT_GOOGLE_AUDIT_FINDING_RULES = [rule_no_key, rule_ok]
