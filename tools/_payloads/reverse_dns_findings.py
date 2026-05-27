"""reverse_dns — findings rules."""
def rule_found(s):
    if not s.get("ptr_found"): return None
    return {"name":"PTR records present (reverse DNS configured)","severity":"POSITIVE",
            "evidence":s.get("ptr_summary",""),
            "remediation":"PTR records are public. Avoid embedding sensitive info (internal hostnames, environment names) in reverse DNS.",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_missing(s):
    if s.get("ptr_found"): return None
    return {"name":"No PTR records (reverse DNS not configured)","severity":"INFO",
            "evidence":f"{s.get('ptr_ip_count',0)} IPs tested, none had PTR",
            "remediation":"Missing PTR can cause email deliverability issues (some receivers reject mail from IPs without rDNS).",
            "cwe":"CWE-200","owasp":"M2:2023"}

REVERSE_DNS_FINDING_RULES = [rule_found, rule_missing]
