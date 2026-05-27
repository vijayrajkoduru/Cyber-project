"""ipv6_alive_enum findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"IPv6 reachable host enum requires THC_IPV6_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add THC_IPV6_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"IPv6 reachable host enum API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
IPV6_ALIVE_ENUM_FINDING_RULES = [rule_no_key, rule_ok]
