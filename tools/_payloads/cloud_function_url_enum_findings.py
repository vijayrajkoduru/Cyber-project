"""cloud_function_url_enum findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Cloud function URL enum requires CLOUD_KEYS","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add CLOUD_KEYS to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Cloud function URL enum API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
CLOUD_FUNCTION_URL_ENUM_FINDING_RULES = [rule_no_key, rule_ok]
