"""hunter_io_email_pattern findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Hunter.io email pattern requires HUNTER_API_KEY","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add HUNTER_API_KEY to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Hunter.io email pattern API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
HUNTER_IO_EMAIL_PATTERN_FINDING_RULES = [rule_no_key, rule_ok]
