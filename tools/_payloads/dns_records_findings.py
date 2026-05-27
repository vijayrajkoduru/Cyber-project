"""dns_records — findings rules."""
def rule_found(s):
    if not s.get("dns_records_found"): return None
    return {"name":f"DNS records retrieved ({s.get('dns_total_records',0)} total)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"Types: {s.get('dns_record_types','')}. A={s.get('dns_a','')}. NS={s.get('dns_ns','')}",
            "remediation":"DNS records are public by design. Audit TXT records for sensitive leakage (verification tokens, etc.)."}

def rule_not_found(s):
    if s.get("dns_records_found"): return None
    return {"name":"DNS resolution failed","severity":"HIGH","cvss":"5.0",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":"dnspython returned no records",
            "remediation":"Domain may be unregistered or DNS servers unreachable."}

DNS_RECORDS_FINDING_RULES = [rule_found, rule_not_found]
