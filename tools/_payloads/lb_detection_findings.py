"""lb_detection — findings rules."""
def rule_multi(s):
    if not s.get("lb_is_multi"): return None
    return {"name":f"Load balancing detected ({s.get('lb_ip_count',0)} IPs in rotation)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M5:2023",
            "evidence":f"IPs: {s.get('lb_ips_sample','')}, min TTL: {s.get('lb_min_ttl',0)}s",
            "remediation":"Multi-IP setup = better availability + DDoS resilience. Test each origin individually for misconfigured backends."}

def rule_low_ttl(s):
    if not s.get("lb_low_ttl") or not s.get("lb_is_multi"): return None
    return {"name":f"Very low DNS TTL ({s.get('lb_min_ttl',0)}s) — fast failover","severity":"INFO",
            "cwe":"CWE-200","owasp":"M5:2023",
            "evidence":f"Min TTL: {s.get('lb_min_ttl',0)}s",
            "remediation":"Low TTL enables fast failover but increases DNS query load. Consider 60-300s baseline unless rapid failover is required."}

def rule_single(s):
    if s.get("lb_is_multi") or s.get("lb_ip_count", 0) == 0: return None
    return {"name":"Single IP (no DNS-level load balancing)","severity":"INFO",
            "evidence":f"IP: {s.get('lb_ips_sample','')}",
            "remediation":"Single-IP setups are vulnerable to single-point-of-failure. Consider DNS-LB, anycast, or CDN.",
            "cwe":"CWE-200","owasp":"M5:2023"}

LB_DETECTION_FINDING_RULES = [rule_multi, rule_low_ttl, rule_single]
