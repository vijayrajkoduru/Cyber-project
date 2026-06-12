"""anycast_detect — findings rules."""
def rule_anycast(s):
    if not s.get("ac_is_anycast"): return None
    prov = s.get("ac_anycast_provider", "")
    return {"name":f"Anycast nameservers detected{' (' + prov + ')' if prov else ''}","severity":"POSITIVE",
            "evidence":f"{s.get('ac_ns_count',0)} NS records, {s.get('ac_ns_ip_count',0)} unique IPs",
            "remediation":"Anycast NS = better DDoS resilience + geographic distribution. Maintain.",
            "cwe":"CWE-200","owasp":"M5:2023"}

def rule_unicast(s):
    if s.get("ac_is_anycast") or s.get("ac_ns_count", 0) == 0: return None
    return {"name":"Likely unicast nameservers (no anycast detected)","severity":"INFO",
            "evidence":f"{s.get('ac_ns_count',0)} NS records, {s.get('ac_ns_ip_count',0)} IPs, no major provider match",
            "remediation":"Consider switching to anycast DNS (Cloudflare, AWS Route53, Azure DNS, Google Cloud DNS) for better DDoS resilience.",
            "cwe":"CWE-200","owasp":"M5:2023"}

ANYCAST_DETECT_FINDING_RULES = [rule_anycast, rule_unicast,
]

def rule_positive_emit(s):
    """POSITIVE-emit when no risk indicators present (VL-FORGE pattern)."""
    if s.get("anycast_detected") or s.get("anycast_providers"):
        return None
    return {
        "name": "No anycast nameserver detected",
        "severity": "POSITIVE",
        "evidence": "Single-region NS resolved from probe IPs",
        "remediation": "Anycast is optional - useful for latency reduction but not a security requirement.",
        "cwe": "CWE-200", "owasp": "N/A"
    }

ANYCAST_DETECT_FINDING_RULES.append(rule_positive_emit)
