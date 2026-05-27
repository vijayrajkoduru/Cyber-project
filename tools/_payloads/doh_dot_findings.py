"""doh_dot — findings rules."""
def rule_both(s):
    if not (s.get("doh_supported") and s.get("dot_supported")): return None
    return {"name":"DNS over HTTPS + DNS over TLS both supported","severity":"POSITIVE",
            "evidence":"DoH on :443/dns-query + DoT on :853",
            "remediation":"Maintain — encrypted DNS available for security-conscious users.",
            "cwe":"CWE-200","owasp":"M5:2023"}

def rule_only_doh(s):
    if not s.get("doh_supported") or s.get("dot_supported"): return None
    return {"name":"DoH only — DNS over TLS missing","severity":"INFO",
            "evidence":"DoH at /dns-query works but port 853 doesn't respond to TLS-ALPN dot",
            "remediation":"Consider also offering DoT — preferred by some clients/CDNs.",
            "cwe":"CWE-200","owasp":"M5:2023"}

def rule_only_dot(s):
    if not s.get("dot_supported") or s.get("doh_supported"): return None
    return {"name":"DoT only — DNS over HTTPS missing","severity":"INFO",
            "evidence":"DoT on :853 works but DoH at /dns-query doesn't",
            "remediation":"Consider also offering DoH — easier for browsers.",
            "cwe":"CWE-200","owasp":"M5:2023"}

def rule_none(s):
    if s.get("doh_supported") or s.get("dot_supported"): return None
    return {"name":"No encrypted DNS (no DoH/DoT)","severity":"INFO",
            "evidence":"Neither :443/dns-query nor :853 responded as expected",
            "remediation":"Not required, but encrypted DNS is increasingly expected for privacy-conscious users.",
            "cwe":"CWE-200","owasp":"M5:2023"}

DOH_DOT_FINDING_RULES = [rule_both, rule_only_doh, rule_only_dot, rule_none]
