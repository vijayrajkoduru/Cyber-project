"""banner_grab findings."""

def rule_f(s):
    c = s.get("banner_count") or 0
    if c == 0: return None
    return {"name":f"Service banners leak: {c}","severity":"LOW","cvss":"3.7",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("banner_sample",""),
            "remediation":"Strip version banners. Disable verbose greetings on SSH/SMTP/POP/IMAP/Redis/Memcached."}
def rule_n(s):
    if (s.get("banner_count") or 0) > 0: return None
    return {"name":"No service banners leaked","severity":"POSITIVE",
            "evidence":"No version info in banners","remediation":"Maintain.",
            "cwe":"CWE-200","owasp":"M2:2023"}
BANNER_GRAB_FINDING_RULES = [rule_f, rule_n]
