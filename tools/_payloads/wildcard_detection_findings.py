"""wildcard_detection — findings rules."""
def rule_wildcard(s):
    if not s.get("wildcard_present"): return None
    return {"name":"DNS wildcard record detected","severity":"INFO",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"{s.get('wildcard_probes_resolved',0)}/4 random subdomains resolved → IPs: {s.get('wildcard_ips_sample','')}",
            "remediation":"Wildcards cause false positives in subdomain enumeration. Document the wildcard target so subdomain brute-force tools can filter. NOT a vulnerability per se."}

def rule_no_wildcard(s):
    if s.get("wildcard_present"): return None
    return {"name":"No DNS wildcard configured","severity":"POSITIVE",
            "evidence":"4 random subdomain probes all returned NXDOMAIN",
            "remediation":"Clean — subdomain enumeration tools won't get false positives.",
            "cwe":"CWE-200","owasp":"M2:2023"}

WILDCARD_DETECTION_FINDING_RULES = [rule_wildcard, rule_no_wildcard]
