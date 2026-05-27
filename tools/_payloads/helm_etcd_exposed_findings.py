"""helm_etcd_exposed findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Helm/etcd exposure requires HELM_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add HELM_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Helm/etcd exposure API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
HELM_ETCD_EXPOSED_FINDING_RULES = [rule_no_key, rule_ok]
