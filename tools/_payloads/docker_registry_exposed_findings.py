"""docker_registry_exposed findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Docker registry exposure requires DOCKER_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add DOCKER_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Docker registry exposure API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
DOCKER_REGISTRY_EXPOSED_FINDING_RULES = [rule_no_key, rule_ok]
