"""uspto_patent — findings rules."""
def rule_found(s):
    c = s.get("uspto_count") or 0
    if c == 0: return None
    return {"name":f"USPTO patents: {c} patent(s) assigned to this organization","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("uspto_sample",""),
            "remediation":"Patents reveal R&D direction + technology stack. Useful business intelligence; not a vulnerability."}

def rule_none(s):
    if (s.get("uspto_count") or 0) > 0: return None
    return {"name":"No USPTO patents found","severity":"INFO",
            "evidence":f"Keyword '{s.get('uspto_keyword','')}' returned 0 patents",
            "remediation":"Organization may not file US patents, or assignee name differs from domain keyword.",
            "cwe":"CWE-200","owasp":"M2:2023"}

USPTO_PATENT_FINDING_RULES = [rule_found, rule_none]
