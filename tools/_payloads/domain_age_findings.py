"""domain_age — findings rules."""
def rule_age(s):
    if not s.get("domain_age_found"): return None
    age = s.get("age_days") or 0
    years = s.get("age_years") or 0
    if age < 90:
        return {"name":f"Newly-registered domain ({age} days old)","severity":"MEDIUM","cvss":"4.3",
                "cwe":"CWE-345","owasp":"M2:2023",
                "evidence":f"created={s.get('created','?')} ({years} years)",
                "remediation":"Newly-registered domains are statistically associated with phishing/malware. If this is unexpected, investigate ownership."}
    return {"name":f"Established domain ({years} years, {age} days)","severity":"POSITIVE",
            "evidence":f"created={s.get('created','?')}",
            "remediation":"Long-lived domain = higher trust signal.",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_expiry(s):
    d = s.get("days_to_expiry")
    if d is None: return None
    if d < 0:
        return {"name":"Domain has EXPIRED","severity":"HIGH","cvss":"7.5",
                "cwe":"CWE-1395","owasp":"M2:2023",
                "evidence":f"expires={s.get('expires','?')}, days_to_expiry={d}",
                "remediation":"Renew immediately — expired domains are vulnerable to hijacking + identity attacks."}
    if d < 30:
        return {"name":f"Domain expires soon ({d} days)","severity":"MEDIUM","cvss":"4.3",
                "cwe":"CWE-1395","owasp":"M2:2023",
                "evidence":f"expires={s.get('expires','?')}",
                "remediation":"Enable auto-renew or renew immediately. Expiring domains attract squatters."}
    return None

DOMAIN_AGE_FINDING_RULES = [rule_age, rule_expiry
]

