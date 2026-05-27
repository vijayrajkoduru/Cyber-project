"""subdomain_bruteforce — findings rules."""
def rule_found(s):
    c = s.get("bf_count") or 0
    if c == 0: return None
    return {"name":f"Subdomain brute-force: {c} subdomain(s) discovered","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("bf_sample",""),
            "remediation":"Each discovered subdomain is an additional attack surface. Audit non-production subdomains (dev/staging/test) for over-exposure."}

def rule_none(s):
    if (s.get("bf_count") or 0) > 0: return None
    return {"name":"No common subdomains responded","severity":"POSITIVE",
            "evidence":"~80 common subdomain probes returned NXDOMAIN",
            "remediation":"Reduced attack surface — fewer subdomains = fewer entry points.",
            "cwe":"CWE-200","owasp":"M2:2023"}

SUBDOMAIN_BRUTEFORCE_FINDING_RULES = [rule_found, rule_none]
