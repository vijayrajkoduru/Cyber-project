"""permutation_gen — findings rules."""
def rule_found(s):
    c = s.get("pg_count") or 0
    if c == 0: return None
    return {"name":f"Permutation-based discovery: {c} additional subdomain(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("pg_sample",""),
            "remediation":"dev-/staging-/test- variants often have weaker access controls. Audit each discovered permutation for over-exposure."}

def rule_none(s):
    if (s.get("pg_count") or 0) > 0: return None
    return {"name":"No permutation-based subdomains found","severity":"POSITIVE",
            "evidence":f"{s.get('pg_attempted',0)} permutations tried, no DNS hits",
            "remediation":"Maintain — naming variants are not exposed.",
            "cwe":"CWE-200","owasp":"M2:2023"}

PERMUTATION_GEN_FINDING_RULES = [rule_found, rule_none]
