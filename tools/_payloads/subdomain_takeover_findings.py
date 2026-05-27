"""subdomain_takeover — findings rules."""
def rule_vulnerable(s):
    if not s.get("takeover_vulnerable"): return None
    return {"name":f"Subdomain takeover possible ({s.get('takeover_vuln_count',0)} dangling CNAME)","severity":"CRITICAL","cvss":"9.1",
            "cwe":"CWE-350","owasp":"M2:2023",
            "evidence":s.get("takeover_details",""),
            "remediation":"Attacker can claim the cloud resource at the CNAME target and serve content from your domain. Remove the CNAME OR re-claim the cloud resource immediately."}

def rule_safe(s):
    if s.get("takeover_vulnerable") or s.get("takeover_checked", 0) == 0: return None
    return {"name":"No subdomain takeover detected","severity":"POSITIVE",
            "evidence":s.get("takeover_details",""),
            "remediation":"Maintain — CNAMEs (if any) point to active cloud resources.",
            "cwe":"CWE-350","owasp":"M2:2023"}

SUBDOMAIN_TAKEOVER_FINDING_RULES = [rule_vulnerable, rule_safe,
    rule_positive_emit,
]

def rule_positive_emit(s):
    """POSITIVE-emit when no risk indicators present (VL-FORGE pattern)."""
    if s.get("takeover_vulnerable") or s.get("dangling_cnames"):
        return None
    return {
        "name": "No dangling CNAMEs vulnerable to cloud takeover",
        "severity": "POSITIVE",
        "evidence": "All CNAMEs resolve to active providers",
        "remediation": "Maintain - inventory CNAMEs quarterly and remove dangling refs to decommissioned services.",
        "cwe": "CWE-200", "owasp": "N/A"
    }
