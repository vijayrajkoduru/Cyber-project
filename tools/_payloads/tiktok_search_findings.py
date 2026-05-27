"""tiktok_search — findings rules."""
def rule_found(s):
    c = s.get("tt_handle_count") or 0
    if c == 0: return None
    return {"name":f"TikTok presence: {c} handle(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("tt_handles",""),
            "remediation":"TikTok videos can leak office layouts, employee daily routines, sometimes badge layouts. Audit corporate accounts for sensitive content."}

def rule_none(s):
    if (s.get("tt_handle_count") or 0) > 0: return None
    return {"name":"No TikTok presence found","severity":"POSITIVE",
            "evidence":"site:tiktok.com/@ returned no matches",
            "remediation":"No TikTok OSINT footprint.",
            "cwe":"CWE-200","owasp":"M2:2023"}

TIKTOK_SEARCH_FINDING_RULES = [rule_found, rule_none]
