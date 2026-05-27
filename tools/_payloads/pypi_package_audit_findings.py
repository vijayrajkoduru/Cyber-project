"""pypi_package_audit findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"PyPI package audit requires PYPI_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add PYPI_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"PyPI package audit API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
PYPI_PACKAGE_AUDIT_FINDING_RULES = [rule_no_key, rule_ok]
