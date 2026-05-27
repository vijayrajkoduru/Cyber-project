"""security_txt findings."""

def rule_present(s):
    if not s.get("sectxt_found"): return None
    return {"name":"security.txt present (RFC 9116)","severity":"POSITIVE",
            "evidence":f"Contact: {s.get('sectxt_contact','?')}",
            "remediation":"Maintain — enables responsible disclosure.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_missing(s):
    if s.get("sectxt_found"): return None
    return {"name":"No security.txt","severity":"INFO",
            "evidence":"No /.well-known/security.txt or /security.txt",
            "remediation":"Add /.well-known/security.txt per RFC 9116 to enable responsible disclosure (Contact: security@yourdomain).",
            "cwe":"CWE-200","owasp":"M2:2023"}
SECURITY_TXT_FINDING_RULES = [rule_present, rule_missing]
