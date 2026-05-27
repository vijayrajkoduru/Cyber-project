"""search_engine_scrape — findings rules."""
def rule_found(s):
    c = s.get("se_count") or 0
    if c == 0: return None
    return {"name":f"Search engines indexed {c} subdomain(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("se_sample",""),
            "remediation":"Subdomains indexed by search engines are easily found by attackers. Use robots.txt + noindex meta for dev/staging."}

def rule_none(s):
    if (s.get("se_count") or 0) > 0: return None
    return {"name":"No subdomains indexed by search engines","severity":"POSITIVE",
            "evidence":"DuckDuckGo + Bing returned no site: matches",
            "remediation":"Maintain — limits passive enumeration via search.",
            "cwe":"CWE-200","owasp":"M2:2023"}

SEARCH_ENGINE_SCRAPE_FINDING_RULES = [rule_found, rule_none]
