"""gha_secret_leak_logs findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"GitHub Actions secret leak in logs requires GITHUB_TOKEN","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add GITHUB_TOKEN to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"GitHub Actions secret leak in logs API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
GHA_SECRET_LEAK_LOGS_FINDING_RULES = [rule_no_key, rule_ok]
