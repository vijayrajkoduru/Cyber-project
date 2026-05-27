"""cors_misconfig findings."""

def rule_vuln(s):
    if not s.get("vulnerable"): return None
    issues = []
    if s.get("reflected_origin"): issues.append("origin reflection")
    if s.get("null_allowed"): issues.append("null origin allowed")
    if s.get("wildcard_with_creds"): issues.append("wildcard + credentials")
    return {"name":f"CORS misconfiguration ({', '.join(issues)})","severity":"HIGH","cvss":"7.1",
            "cwe":"CWE-942","owasp":"M5:2023",
            "evidence":f"Issues: {', '.join(issues)}",
            "remediation":"Whitelist explicit origins. Never reflect Origin into Access-Control-Allow-Origin with credentials=true. Never allow null origin."}
def rule_safe(s):
    if s.get("vulnerable"): return None
    return {"name":"CORS configuration safe","severity":"POSITIVE",
            "evidence":"No origin reflection, no null, no wildcard+creds","remediation":"Maintain.",
            "cwe":"CWE-942","owasp":"M5:2023"}
CORS_MISCONFIG_FINDING_RULES = [rule_vuln, rule_safe]
