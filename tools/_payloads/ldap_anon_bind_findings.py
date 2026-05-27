"""ldap_anon_bind findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"LDAP anonymous bind requires LDAP_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add LDAP_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"LDAP anonymous bind API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
LDAP_ANON_BIND_FINDING_RULES = [rule_no_key, rule_ok]
