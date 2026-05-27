"""wayback_timeline — findings rules."""
def rule_positive(s):
    if not s.get("wayback_found"): return None
    return {"name":f"Wayback Machine: {s.get('wayback_snapshots',0)} archived snapshots","severity":"POSITIVE",
            "evidence":f"first={s.get('wayback_first','?')} last={s.get('wayback_last','?')}",
            "remediation":"Historical snapshots may leak old endpoints, secrets, dev URLs. Audit archive.org for sensitive paths.",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_not_found(s):
    if s.get("wayback_found"): return None
    return {"name":"No Wayback Machine snapshots","severity":"INFO",
            "evidence":"CDX API returned no data",
            "remediation":"Site has not been crawled by Internet Archive.",
            "cwe":"CWE-200","owasp":"M2:2023"}

WAYBACK_TIMELINE_FINDING_RULES = [rule_positive, rule_not_found]
