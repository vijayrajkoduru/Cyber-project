"""ip_geo — findings rules."""
def rule_positive(s):
    if not s.get("ip_geo_found"): return None
    return {"name":"IP geolocation + ISP identified","severity":"POSITIVE",
            "evidence":f"{s.get('ip','?')} → {s.get('country','?')} {s.get('city','')}, ISP={s.get('isp','?')}, Org={s.get('org','?')}",
            "remediation":"Geolocation is public — fingerprinting info but not a vulnerability.",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_not_found(s):
    if s.get("ip_geo_found"): return None
    return {"name":"IP geolocation lookup failed","severity":"INFO",
            "evidence":"ip-api.com returned no data",
            "remediation":"Host may not be internet-routable.",
            "cwe":"CWE-200","owasp":"M2:2023"}

IP_GEO_FINDING_RULES = [rule_positive, rule_not_found]
