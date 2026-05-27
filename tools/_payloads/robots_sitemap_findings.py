"""robots_sitemap findings."""

def rule_disallow(s):
    c = s.get("disallow_count") or 0
    if c == 0: return None
    return {"name":f"robots.txt Disallow: {c} path(s) — recon-friendly list","severity":"INFO",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("disallow_sample",""),
            "remediation":"robots.txt Disallow is a polite request to crawlers; it also tells attackers exactly what you DON'T want crawled. Move sensitive paths off-site or behind auth."}
def rule_present(s):
    if not s.get("robots_present"): return None
    if (s.get("disallow_count") or 0) > 0: return None
    return {"name":"robots.txt present (no Disallow)","severity":"POSITIVE",
            "evidence":"robots.txt accessible, no path disclosure","remediation":"Maintain.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_missing(s):
    if s.get("robots_present"): return None
    return {"name":"No robots.txt","severity":"INFO",
            "evidence":"GET /robots.txt returned non-200","remediation":"Not required, but standard practice.",
            "cwe":"CWE-200","owasp":"M2:2023"}
ROBOTS_SITEMAP_FINDING_RULES = [rule_disallow, rule_present, rule_missing]
