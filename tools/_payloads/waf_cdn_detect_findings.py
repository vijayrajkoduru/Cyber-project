"""waf_cdn_detect findings."""

def rule_f(s):
    w = s.get("wafs") or []
    if not w: return None
    return {"name":f"WAF/CDN: {', '.join(w)}","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M5:2023",
            "evidence":", ".join(w),"remediation":"WAF/CDN present — good defense layer. Test for origin-IP bypass via CDN dodge."}
def rule_n(s):
    if (s.get("wafs") or []): return None
    return {"name":"No WAF/CDN detected","severity":"LOW","cvss":"3.1",
            "cwe":"CWE-693","owasp":"M5:2023",
            "evidence":"No WAF/CDN headers in HTTP response",
            "remediation":"Consider Cloudflare/AWS WAF/Imperva for L7 DDoS + OWASP rule protection."}
WAF_CDN_DETECT_FINDING_RULES = [rule_f, rule_n]
