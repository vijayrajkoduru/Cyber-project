"""sec_edgar — findings rules."""
def rule_found(s):
    c = s.get("sec_match_count") or 0
    if c == 0: return None
    return {"name":f"SEC EDGAR matches: {c} company filing(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("sec_sample",""),
            "remediation":"Publicly-filed SEC documents reveal financial structure, subsidiaries, executive names. Useful for context, not a vulnerability."}

def rule_none(s):
    if (s.get("sec_match_count") or 0) > 0: return None
    return {"name":"No SEC EDGAR filings for this keyword","severity":"INFO",
            "evidence":f"Keyword '{s.get('sec_keyword','')}' returned no SEC matches",
            "remediation":"Private company or non-US — no SEC reporting obligation.",
            "cwe":"CWE-200","owasp":"M2:2023"}

SEC_EDGAR_FINDING_RULES = [rule_found, rule_none]
