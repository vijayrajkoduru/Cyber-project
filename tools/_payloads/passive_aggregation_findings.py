"""passive_aggregation — findings rules."""
def rule_found(s):
    c = s.get("pa_total") or 0
    if c == 0: return None
    return {"name":f"Passive subdomain aggregation: {c} unique subdomain(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("pa_sample",""),
            "remediation":"Each subdomain extends the attack surface. Audit for unintended exposure (dev/staging/internal subdomains in public CT logs)."}

def rule_none(s):
    if (s.get("pa_total") or 0) > 0: return None
    return {"name":"No subdomains found in passive sources","severity":"POSITIVE",
            "evidence":"crt.sh + hackertarget + certspotter returned empty",
            "remediation":"Reduced attack surface — no subdomain inventory leaking to public CT/DNS feeds.",
            "cwe":"CWE-200","owasp":"M2:2023"}

PASSIVE_AGGREGATION_FINDING_RULES = [rule_found, rule_none]
