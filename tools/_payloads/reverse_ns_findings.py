"""reverse_ns — findings rules."""
def rule_shared_ns(s):
    c = s.get("shared_count") or 0
    if c == 0: return None
    return {"name":f"Shared nameserver — {c} other domain(s)","severity":"INFO",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"NS: {s.get('nameservers','?')}. Sample others: {s.get('shared_sample','')}",
            "remediation":"Shared NS reveals organization grouping. For high-confidentiality assets, consider dedicated NS infrastructure."}

def rule_solo(s):
    if not s.get("reverse_ns_found") or (s.get("shared_count") or 0) > 0: return None
    return {"name":"No other domains found on these nameservers","severity":"POSITIVE",
            "evidence":f"NS: {s.get('nameservers','?')}",
            "remediation":"Reduces grouping-attribution attack surface.",
            "cwe":"CWE-200","owasp":"M2:2023"}

REVERSE_NS_FINDING_RULES = [rule_shared_ns, rule_solo
]

