"""email_harvester findings."""

def rule_f(s):
    c = s.get("email_count") or 0
    if c == 0: return None
    return {"name":f"Email addresses harvested: {c}","severity":"INFO",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("emails_sample",""),
            "remediation":"Public-facing emails are recon-friendly. Audit each for phishing target risk. Add DMARC reject + anti-spoofing."}
def rule_n(s):
    if (s.get("email_count") or 0) > 0: return None
    return {"name":"No public emails harvested","severity":"POSITIVE",
            "evidence":"Search returned no @domain matches","remediation":"Reduced phishing target surface.",
            "cwe":"CWE-200","owasp":"M2:2023"}
EMAIL_HARVESTER_FINDING_RULES = [rule_f, rule_n]
