"""email_security — findings rules."""
def rule_no_spf(s):
    if s.get("spf_present"): return None
    return {"name":"No SPF record — domain spoofable via email","severity":"HIGH","cvss":"6.5",
            "cwe":"CWE-290","owasp":"M2:2023",
            "evidence":"No TXT v=spf1 record found",
            "remediation":"Add SPF record. Minimum: `v=spf1 -all` if you don't send email; or `v=spf1 include:_spf.google.com -all` for Google Workspace."}

def rule_weak_spf(s):
    if not s.get("spf_present") or s.get("spf_strict"): return None
    return {"name":"SPF record uses soft-fail (~all)","severity":"MEDIUM","cvss":"4.3",
            "cwe":"CWE-290","owasp":"M2:2023",
            "evidence":s.get("spf",""),
            "remediation":"Change `~all` to `-all` for hard-fail enforcement."}

def rule_no_dmarc(s):
    if s.get("dmarc_present"): return None
    return {"name":"No DMARC record","severity":"HIGH","cvss":"6.5",
            "cwe":"CWE-290","owasp":"M2:2023",
            "evidence":"No TXT v=DMARC1 record at _dmarc.<domain>",
            "remediation":"Add `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com` to _dmarc.<domain>."}

def rule_weak_dmarc(s):
    p = s.get("dmarc_policy")
    if not s.get("dmarc_present") or p == "reject": return None
    return {"name":f"DMARC policy is '{p}' (not enforcing reject)","severity":"MEDIUM","cvss":"4.3",
            "cwe":"CWE-290","owasp":"M2:2023",
            "evidence":s.get("dmarc",""),
            "remediation":"Tighten DMARC policy from 'none'/'quarantine' to 'reject' after monitoring period."}

def rule_dkim_missing(s):
    if s.get("dkim_present"): return None
    return {"name":"No DKIM record found (tried common selectors)","severity":"MEDIUM","cvss":"4.3",
            "cwe":"CWE-290","owasp":"M2:2023",
            "evidence":"Selectors tried: default, google, selector1, mail, k1, etc.",
            "remediation":"Configure DKIM in your mail provider (selector + public key in DNS)."}

def rule_all_present(s):
    if not (s.get("spf_present") and s.get("dmarc_present") and s.get("dkim_present")): return None
    if not s.get("spf_strict") or s.get("dmarc_policy") != "reject": return None
    return {"name":"Email security fully enforced (SPF -all + DKIM + DMARC reject)","severity":"POSITIVE",
            "evidence":"All three protocols configured strictly",
            "remediation":"Maintain — domain is well-protected against spoofing.",
            "cwe":"CWE-290","owasp":"M2:2023"}

EMAIL_SECURITY_FINDING_RULES = [rule_no_spf, rule_weak_spf, rule_no_dmarc, rule_weak_dmarc, rule_dkim_missing, rule_all_present]
