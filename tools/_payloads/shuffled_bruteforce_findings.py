"""shuffled_bruteforce — findings rules."""
def rule_found(s):
    c = s.get("sh_real_hits") or 0
    if c == 0: return None
    msg = f"Wildcard-aware brute-force: {c} real subdomain(s)"
    if s.get("sh_wildcard_present"):
        msg += f" (filtered {s.get('sh_wildcard_hits',0)} wildcard false-positives)"
    return {"name":msg,"severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("sh_sample",""),
            "remediation":"Wildcard-aware brute gives high-confidence results. Investigate each subdomain for unintended exposure."}

def rule_none(s):
    if (s.get("sh_real_hits") or 0) > 0: return None
    return {"name":"No subdomains discovered via wildcard-aware brute","severity":"POSITIVE",
            "evidence":f"{s.get('sh_attempted',0)} probes tried",
            "remediation":"Maintain — reduced subdomain attack surface.",
            "cwe":"CWE-200","owasp":"M2:2023"}

SHUFFLED_BRUTEFORCE_FINDING_RULES = [rule_found, rule_none]
