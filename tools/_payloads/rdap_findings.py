"""rdap — findings rules."""
def rule_positive(s):
    if not s.get("rdap_found"): return None
    return {"name":"RDAP record retrieved","severity":"POSITIVE",
            "evidence":f"handle={s.get('rdap_handle','?')}, created={s.get('rdap_created','?')}, status={s.get('rdap_status','?')}",
            "remediation":"RDAP exposes structured WHOIS; modern registries provide this by default.",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_not_found(s):
    if s.get("rdap_found"): return None
    return {"name":"RDAP returned no data","severity":"INFO",
            "evidence":"rdap.org returned non-200 or empty body",
            "remediation":"Some TLDs don't support RDAP yet; fall back to WHOIS.",
            "cwe":"CWE-200","owasp":"M2:2023"}

RDAP_FINDING_RULES = [rule_positive, rule_not_found]
