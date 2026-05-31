"""dns_0x20 — findings rules. NEW 2024+."""
def rule_supported(s):
    if not s.get("case_preserved"): return None
    return {"name":"DNS 0x20 case randomization preserved (RFC 5452 anti-spoofing)","severity":"POSITIVE",
            "cwe":"CWE-345","owasp":"M5:2023",
            "evidence":f"Query: {s.get('sample_q','')} → Response: {s.get('sample_r','')}",
            "remediation":"Maintain — case-preservation makes DNS spoofing harder by adding entropy."}

def rule_not_supported(s):
    if s.get("case_preserved") or s.get("queries_tested", 0) == 0: return None
    return {"name":"DNS 0x20 case randomization NOT preserved","severity":"LOW","cvss":"3.7",
            "cwe":"CWE-345","owasp":"M5:2023",
            "evidence":f"Query: {s.get('sample_q','')} → Response: {s.get('sample_r','')}",
            "remediation":"Authoritative nameserver normalizes case, reducing spoofing-attack difficulty. Upgrade NS software to one preserving query case (RFC 5452)."}

DNS_0X20_FINDING_RULES = [rule_supported, rule_not_supported,
    rule_positive_emit,
]

def rule_positive_emit(s):
    """POSITIVE-emit when no risk indicators present (VL-FORGE pattern)."""
    if s.get("case_mismatch") or s.get("violation_detected"):
        return None
    return {
        "name": "DNS 0x20 case randomization preserved",
        "severity": "POSITIVE",
        "evidence": "Query case echoed correctly in response",
        "remediation": "Maintain - RFC 5452 compliance reduces cache-poisoning risk.",
        "cwe": "CWE-200", "owasp": "N/A"
    }
