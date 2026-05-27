"""azure_app_services findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Azure App Services requires AZURE_KEYS","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add AZURE_KEYS to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Azure App Services API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
AZURE_APP_SERVICES_FINDING_RULES = [rule_no_key, rule_ok]
