"""service_version_detect findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Nmap service+version (-sV) requires NMAP_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add NMAP_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Nmap service+version (-sV) API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
SERVICE_VERSION_DETECT_FINDING_RULES = [rule_no_key, rule_ok]
