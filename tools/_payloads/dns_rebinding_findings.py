"""dns_rebinding — findings rules. NEW 2024+."""
def rule_private_ips_in_public_dns(s):
    if not s.get("dr_susceptible"): return None
    return {"name":f"Private/internal IPs in public DNS ({s.get('dr_private_count',0)} found)","severity":"HIGH","cvss":"7.1",
            "cwe":"CWE-918","owasp":"M5:2023",
            "evidence":f"Private IPs leaked: {s.get('dr_private_ips','')}",
            "remediation":"REMOVE private IPs from public DNS — enables DNS rebinding attacks (browser can be tricked into hitting internal endpoints). Use split-horizon DNS instead."}

def rule_low_ttl_warning(s):
    if not s.get("dr_low_ttl"): return None
    return {"name":f"Very low DNS TTL ({s.get('dr_soa_ttl',0)}s) — DNS rebinding enabler","severity":"LOW","cvss":"3.1",
            "cwe":"CWE-918","owasp":"M5:2023",
            "evidence":f"SOA TTL: {s.get('dr_soa_ttl',0)}s",
            "remediation":"Low TTL helps DNS rebinding attacks. Use min TTL ≥ 60s unless rapid failover is critical."}

def rule_secure(s):
    if s.get("dr_susceptible") or s.get("dr_low_ttl") or s.get("dr_all_ip_count", 0) == 0: return None
    return {"name":"No DNS rebinding susceptibility detected","severity":"POSITIVE",
            "evidence":f"All {s.get('dr_all_ip_count',0)} IPs public, TTL {s.get('dr_soa_ttl',-1)}s",
            "remediation":"Maintain — DNS not exposing internal IPs and TTL is reasonable.",
            "cwe":"CWE-918","owasp":"M5:2023"}

DNS_REBINDING_FINDING_RULES = [rule_private_ips_in_public_dns, rule_low_ttl_warning, rule_secure]
