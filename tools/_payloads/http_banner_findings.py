"""http_banner findings."""

def rule_f(s):
    if not s.get("found"): return None
    server = s.get("server","")
    xp = s.get("x_powered_by","")
    sev = "LOW" if (server or xp) else "POSITIVE"
    return {"name":f"HTTP banner: {server or '(no Server header)'}{', X-Powered-By: ' + xp if xp else ''}","severity":sev,"cvss":"3.1" if sev=="LOW" else "",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"status={s.get('status','?')}, server='{server}', x-powered-by='{xp}'",
            "remediation":"Strip Server + X-Powered-By headers to reduce fingerprinting." if sev=="LOW" else "Maintain — minimal fingerprint."}
def rule_n(s):
    if s.get("found"): return None
    return {"name":"Host not reachable on HTTP/HTTPS","severity":"INFO",
            "evidence":"Both ports unreachable","remediation":"Host may not be a web server.",
            "cwe":"CWE-200","owasp":"M2:2023"}
HTTP_BANNER_FINDING_RULES = [rule_f, rule_n]
