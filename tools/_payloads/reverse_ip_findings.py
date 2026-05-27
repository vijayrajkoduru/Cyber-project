"""reverse_ip — findings rules."""
def rule_shared_ip(s):
    c = s.get("sibling_count") or 0
    if c == 0: return None
    sev = "MEDIUM" if c > 50 else "LOW" if c > 5 else "INFO"
    return {"name":f"Shared IP — {c} sibling domain(s) on same host","severity":sev,
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"IP {s.get('ip','?')} hosts {c} other domains. Sample: {s.get('sibling_sample','')}",
            "remediation":"Shared hosting = lateral risk if a sibling site is compromised. For high-value apps, consider dedicated IP or strict virtual-host isolation."}

def rule_dedicated_ip(s):
    if not s.get("reverse_ip_found") or (s.get("sibling_count") or 0) > 0: return None
    return {"name":"Dedicated IP (no sibling domains)","severity":"POSITIVE",
            "evidence":f"IP {s.get('ip','?')} hosts only this domain",
            "remediation":"Continue with dedicated hosting; minimizes lateral compromise risk.",
            "cwe":"CWE-200","owasp":"M2:2023"}

REVERSE_IP_FINDING_RULES = [rule_shared_ip, rule_dedicated_ip
]

