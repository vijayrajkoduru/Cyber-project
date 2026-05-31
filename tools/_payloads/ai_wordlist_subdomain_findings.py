"""ai_wordlist_subdomain — findings rules. NEW 2024+."""
def rule_found(s):
    c = s.get("ai_wl_count") or 0
    if c == 0: return None
    return {"name":f"AI-curated wordlist: {c} subdomain(s) found","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("ai_wl_sample",""),
            "remediation":"AI-curated lists catch high-value variants (dev/staging/internal/api-v3) that miss in basic brute. Audit each for over-exposure."}

def rule_none(s):
    if (s.get("ai_wl_count") or 0) > 0: return None
    return {"name":"No AI-curated subdomain hits","severity":"POSITIVE",
            "evidence":f"{s.get('ai_wl_attempted',0)} curated probes returned nothing",
            "remediation":"Maintain — minimized subdomain inventory.",
            "cwe":"CWE-200","owasp":"M2:2023"}

AI_WORDLIST_SUBDOMAIN_FINDING_RULES = [rule_found, rule_none]
