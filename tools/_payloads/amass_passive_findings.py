"""amass_passive — findings rules."""
def rule_found(s):
    c = s.get("am_count") or 0
    if c == 0: return None
    return {"name":f"OSINT aggregation: {c} unique subdomain(s) across 4 sources","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("am_sample",""),
            "remediation":"Multi-source passive aggregation catches subdomains missed by single-source lookups. Audit each for over-exposure."}

def rule_none(s):
    if (s.get("am_count") or 0) > 0: return None
    return {"name":"No subdomains found in OSINT aggregation","severity":"POSITIVE",
            "evidence":"AlienVault OTX + ThreatCrowd + URLScan + RapidDNS returned empty",
            "remediation":"Maintain — limited passive-intel footprint.",
            "cwe":"CWE-200","owasp":"M2:2023"}

AMASS_PASSIVE_FINDING_RULES = [rule_found, rule_none]
