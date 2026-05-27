"""trademark_search findings."""

def rule_f(s):
    c = s.get("tm_count") or 0
    if c == 0: return None
    return {"name":f"Trademarks (TMview): {c} match(es)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"{c} trademark records matching domain keyword",
            "remediation":"Trademarks are public. Useful business intelligence; not a vulnerability."}
def rule_n(s):
    if (s.get("tm_count") or 0) > 0: return None
    return {"name":"No trademark matches","severity":"INFO",
            "evidence":"TMview returned 0","remediation":"Either no registrations or keyword mismatch.",
            "cwe":"CWE-200","owasp":"M2:2023"}
TRADEMARK_SEARCH_FINDING_RULES = [rule_f, rule_n]
