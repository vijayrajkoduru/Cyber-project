"""matter_thread_disco findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Matter/Thread/Zigbee discovery requires MATTER_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add MATTER_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Matter/Thread/Zigbee discovery API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
MATTER_THREAD_DISCO_FINDING_RULES = [rule_no_key, rule_ok]
