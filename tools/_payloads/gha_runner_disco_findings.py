"""gha_runner_disco findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"GHA self-hosted runner discovery requires GITHUB_TOKEN","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add GITHUB_TOKEN to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"GHA self-hosted runner discovery API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
GHA_RUNNER_DISCO_FINDING_RULES = [rule_no_key, rule_ok]
