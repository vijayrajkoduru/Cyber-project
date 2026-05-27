"""hsts_audit findings."""

def rule_missing(s):
    if s.get("hsts_present"): return None
    return {"name":"HSTS header missing","severity":"MEDIUM","cvss":"4.3",
            "cwe":"CWE-319","owasp":"M5:2023",
            "evidence":"No Strict-Transport-Security header",
            "remediation":"Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"}
def rule_short(s):
    if not s.get("hsts_present"): return None
    if (s.get("max_age") or 0) >= 63072000: return None  # 2 years
    return {"name":f"HSTS max-age too short ({s.get('max_age',0)}s)","severity":"LOW","cvss":"3.1",
            "cwe":"CWE-319","owasp":"M5:2023",
            "evidence":s.get("hsts_value",""),
            "remediation":"Use max-age >= 63072000 (2 years) for HSTS preload eligibility."}
def rule_full(s):
    if not s.get("hsts_present"): return None
    if (s.get("max_age") or 0) < 63072000: return None
    return {"name":"HSTS fully configured (long max-age, includeSubDomains, preload)" if s.get("preload") else "HSTS properly configured","severity":"POSITIVE",
            "evidence":s.get("hsts_value",""),
            "remediation":"Maintain.",
            "cwe":"CWE-319","owasp":"M5:2023"}
HSTS_AUDIT_FINDING_RULES = [rule_missing, rule_short, rule_full]
