"""wayback_subdomain_extract — findings rules."""
def rule_found(s):
    c = s.get("wse_count") or 0
    if c == 0: return None
    return {"name":f"Wayback Machine: {c} archived subdomain(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("wse_sample",""),
            "remediation":"Historical archives reveal old subdomains, possibly including decommissioned ones — useful for finding dangling DNS pointing to deprovisioned cloud resources (takeover)."}

def rule_none(s):
    if (s.get("wse_count") or 0) > 0: return None
    return {"name":"No subdomains in Wayback archive","severity":"INFO",
            "evidence":"web.archive.org CDX returned no subdomain hits",
            "remediation":"Either site wasn't crawled, or robots.txt blocks archive.",
            "cwe":"CWE-200","owasp":"M2:2023"}

WAYBACK_SUBDOMAIN_EXTRACT_FINDING_RULES = [rule_found, rule_none]
