"""param_discovery findings."""

def rule_f(s):
    c = s.get("param_count") or 0
    if c == 0: return None
    return {"name":f"Reflected parameters: {c}","severity":"INFO",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":", ".join(s.get("params_found",[])[:10]),
            "remediation":"Each reflected param is a potential XSS / SSRF / IDOR test target."}
def rule_n(s):
    if (s.get("param_count") or 0) > 0: return None
    return {"name":"No reflected parameters via baseline diff","severity":"POSITIVE",
            "evidence":"None of 20 common params triggered response variance",
            "remediation":"Static or well-validated pages.",
            "cwe":"CWE-200","owasp":"M2:2023"}
PARAM_DISCOVERY_FINDING_RULES = [rule_f, rule_n]
