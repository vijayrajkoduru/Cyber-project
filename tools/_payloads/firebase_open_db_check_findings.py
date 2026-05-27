"""firebase_open_db_check findings."""

def rule_open(s):
    c = s.get("open_count") or 0
    if c == 0: return None
    return {"name":f"Unauthenticated Firebase database(s): {c}","severity":"CRITICAL","cvss":"9.1",
            "cwe":"CWE-284","owasp":"M3:2023",
            "evidence":s.get("open_urls",""),
            "remediation":"CRITICAL: Firebase Realtime DB without auth = full data exposure. Apply Firebase Security Rules immediately."}
def rule_n(s):
    if (s.get("open_count") or 0) > 0: return None
    return {"name":"No open Firebase databases","severity":"POSITIVE",
            "evidence":"3 common project naming patterns tried","remediation":"Either no Firebase, or auth rules properly applied.",
            "cwe":"CWE-284","owasp":"M3:2023"}
FIREBASE_OPEN_DB_CHECK_FINDING_RULES = [rule_open, rule_n]
