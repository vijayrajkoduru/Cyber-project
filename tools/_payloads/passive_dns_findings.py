"""passive_dns — findings rules."""
def rule_found(s):
    if not s.get("passive_dns_found"): return None
    return {"name":f"Passive DNS: {s.get('host_count',0)} hosts on {s.get('ip_count',0)} IP(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"Hosts: {s.get('hosts_sample','')}. IPs: {s.get('ips_sample','')}",
            "remediation":"Passive DNS leaks subdomain inventory. Treat as recon baseline — pivot subdomains into webapp tier."}

def rule_not_found(s):
    if s.get("passive_dns_found"): return None
    return {"name":"No passive DNS records","severity":"INFO",
            "evidence":"HackerTarget hostsearch returned empty",
            "remediation":"Try SecurityTrails/Farsight DNSDB (paid) for deeper coverage.",
            "cwe":"CWE-200","owasp":"M2:2023"}

PASSIVE_DNS_FINDING_RULES = [rule_found, rule_not_found]
