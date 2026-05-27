"""crt_search — findings rules."""
def rule_positive(s):
    if not s.get("crt_found"): return None
    return {"name":f"Certificate Transparency log retrieved ({s.get('crt_total_certs',0)} certs, {s.get('crt_unique_sans',0)} unique SANs)","severity":"POSITIVE",
            "evidence":f"Sample: {s.get('crt_sans_sample','')}",
            "remediation":"CT logs are public by design (RFC 6962). Avoid putting sensitive internal hostnames in certs.",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_not_found(s):
    if s.get("crt_found"): return None
    return {"name":"No CT logs returned","severity":"INFO",
            "evidence":"crt.sh API returned empty result set",
            "remediation":"Domain may not have HTTPS certs issued.",
            "cwe":"CWE-200","owasp":"M2:2023"}

CRT_SEARCH_FINDING_RULES = [rule_positive, rule_not_found]
