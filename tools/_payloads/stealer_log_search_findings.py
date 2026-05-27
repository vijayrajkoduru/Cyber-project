"""stealer_log_search findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Stealer log search (RedLine/Vidar) requires STEALER_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add STEALER_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Stealer log search (RedLine/Vidar) API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
STEALER_LOG_SEARCH_FINDING_RULES = [rule_no_key, rule_ok]
