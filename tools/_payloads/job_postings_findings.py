"""job_postings — findings rules."""
def rule_found(s):
    c = s.get("job_count") or 0
    if c == 0: return None
    tech = s.get("job_tech_stack", "")
    msg = f"Job postings reveal hiring activity"
    if tech: msg += f" + tech stack ({tech})"
    return {"name":msg,"severity":"INFO",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"{c} posting(s). URLs: {s.get('job_sample_urls','')}",
            "remediation":"Job postings leak internal tech stack (databases, frameworks, tools) — useful for attackers targeting specific CVEs. Consider redacting tech-stack specifics from public postings."}

def rule_none(s):
    if (s.get("job_count") or 0) > 0: return None
    return {"name":"No public job postings found","severity":"INFO",
            "evidence":"5 job sites searched, no hits for keyword",
            "remediation":"No tech-stack leakage via public job postings.",
            "cwe":"CWE-200","owasp":"M2:2023"}

JOB_POSTINGS_FINDING_RULES = [rule_found, rule_none]
