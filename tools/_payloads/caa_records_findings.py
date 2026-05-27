"""caa_records — findings rules."""
def rule_present(s):
    if not s.get("caa_found"): return None
    return {"name":f"CAA records configured ({s.get('caa_records_count',0)})","severity":"POSITIVE",
            "cwe":"CWE-295","owasp":"M5:2023",
            "evidence":s.get("caa_records_list",""),
            "remediation":"CAA records restrict which CAs can issue certs. Maintain — reduces mis-issuance risk."}

def rule_missing(s):
    if s.get("caa_found"): return None
    return {"name":"No CAA records — any CA can issue certificates","severity":"MEDIUM","cvss":"4.3",
            "cwe":"CWE-295","owasp":"M5:2023",
            "evidence":"DNS query returned 0 CAA records",
            "remediation":"Add CAA records (e.g., `0 issue \"letsencrypt.org\"`) to restrict cert issuance to approved CAs. RFC 8659."}

CAA_RECORDS_FINDING_RULES = [rule_present, rule_missing]
