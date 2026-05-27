"""email_smtp_validate findings."""

def rule_catchall(s):
    if not s.get("mx_present"): return None
    if s.get("catchall","").startswith("yes"):
        return {"name":"SMTP catchall accepts ALL addresses","severity":"MEDIUM","cvss":"4.3",
                "cwe":"CWE-200","owasp":"M2:2023",
                "evidence":s.get("catchall",""),
                "remediation":"Catchall makes user enumeration easy + breaks DMARC. Disable catchall, use explicit address lists."}
    return None
def rule_secure(s):
    if not s.get("mx_present") or s.get("catchall","").startswith("yes"): return None
    return {"name":f"SMTP: {s.get('mx_count',0)} MX, no catchall","severity":"POSITIVE",
            "evidence":s.get("catchall","ok"),"remediation":"Maintain.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_no_mail(s):
    if s.get("mx_present"): return None
    return {"name":"No MX records — domain doesn't receive mail","severity":"INFO",
            "evidence":"DNS MX query empty","remediation":"If intentional, add `0 .` MX (RFC 7505) to formally reject mail.",
            "cwe":"CWE-200","owasp":"M2:2023"}
EMAIL_SMTP_VALIDATE_FINDING_RULES = [rule_catchall, rule_secure, rule_no_mail]
