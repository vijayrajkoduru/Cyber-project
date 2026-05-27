"""security_headers findings."""

def rule_missing(s):
    m = s.get("sh_missing") or []
    if not m: return None
    sev = "HIGH" if len(m) >= 5 else "MEDIUM" if len(m) >= 3 else "LOW"
    return {"name":f"{len(m)} security header(s) missing","severity":sev,"cvss":"5.3" if sev=="HIGH" else "4.3" if sev=="MEDIUM" else "3.1",
            "cwe":"CWE-693","owasp":"M5:2023",
            "evidence":", ".join(m),
            "remediation":"Add missing headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)."}
def rule_all(s):
    if (s.get("sh_missing_count") or 0) > 0: return None
    return {"name":"All security headers present","severity":"POSITIVE",
            "evidence":"HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy all set",
            "remediation":"Maintain.",
            "cwe":"CWE-693","owasp":"M5:2023"}
SECURITY_HEADERS_FINDING_RULES = [rule_missing, rule_all]
