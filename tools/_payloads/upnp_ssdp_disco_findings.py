"""upnp_ssdp_disco findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"UPnP/SSDP discovery requires UPNP_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add UPNP_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"UPnP/SSDP discovery API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
UPNP_SSDP_DISCO_FINDING_RULES = [rule_no_key, rule_ok]
