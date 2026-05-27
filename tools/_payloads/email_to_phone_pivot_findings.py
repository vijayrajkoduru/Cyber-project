"""email_to_phone_pivot findings."""

def rule_f(s):
    if s.get("needs_api_key"): return None
    c = s.get("pivot_count") or 0
    if c == 0: return None
    return {"name":f"Email→phone pivot: {c} phone source(s)","severity":"MEDIUM","cvss":"4.0",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("pivot_sample",""),
            "remediation":"Email pivots to phone enable SMS phishing + SIM swap targeting. Use unique emails per service."}
def rule_no_key(s):
    if not s.get("needs_api_key"): return None
    return {"name":"Email→phone pivot requires OSINT_INDUSTRIES_API_KEY","severity":"INFO",
            "evidence":"Configure env var","remediation":"Add OSINT_INDUSTRIES_API_KEY.",
            "cwe":"CWE-200","owasp":"M2:2023"}
EMAIL_TO_PHONE_PIVOT_FINDING_RULES = [rule_f, rule_no_key]
