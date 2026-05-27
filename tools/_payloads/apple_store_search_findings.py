"""apple_store_search findings."""

def rule_f(s):
    c = s.get("app_count") or 0
    if c == 0: return None
    return {"name":f"Apple App Store apps: {c}","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("app_sample",""),
            "remediation":"iOS apps extend attack surface. Audit via mobile_static module."}
def rule_n(s):
    if (s.get("app_count") or 0) > 0: return None
    return {"name":"No iOS apps","severity":"POSITIVE",
            "evidence":"iTunes Search empty","remediation":"No iOS attack surface.",
            "cwe":"CWE-200","owasp":"M2:2023"}
APPLE_STORE_SEARCH_FINDING_RULES = [rule_f, rule_n]
