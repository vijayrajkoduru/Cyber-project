"""sherlock_username — findings rules."""
def rule_found(s):
    c = s.get("sherlock_count") or 0
    if c == 0: return None
    return {"name":f"Username '{s.get('sherlock_keyword','')}' present on {c} platform(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"Platforms: {s.get('sherlock_platforms','')}. URLs: {s.get('sherlock_urls','')}",
            "remediation":"Same username across platforms enables OSINT pivoting + identity correlation. Audit each profile for sensitive info."}

def rule_none(s):
    if (s.get("sherlock_count") or 0) > 0: return None
    return {"name":"Username not found on common platforms","severity":"POSITIVE",
            "evidence":f"'{s.get('sherlock_keyword','')}' returned no matches on 15 platforms",
            "remediation":"Reduced cross-platform identity-correlation attack surface.",
            "cwe":"CWE-200","owasp":"M2:2023"}

SHERLOCK_USERNAME_FINDING_RULES = [rule_found, rule_none]
