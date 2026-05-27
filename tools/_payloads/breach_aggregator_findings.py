"""breach_aggregator findings."""

def rule_f(s):
    c = s.get("total_breaches") or 0
    if c == 0: return None
    sev = "HIGH" if c > 5 else "MEDIUM" if c > 1 else "LOW"
    return {"name":f"Breach aggregator: {c} known breach(es)","severity":sev,"cvss":"7.5" if sev=="HIGH" else "5.3",
            "cwe":"CWE-200","owasp":"M9:2023",
            "evidence":f"HIBP: {s.get('hibp_sample','')}",
            "remediation":"Each breach reveals customer credentials. Force password rotation, enable MFA, monitor HIBP for new entries."}
def rule_n(s):
    if (s.get("total_breaches") or 0) > 0: return None
    return {"name":"No known breaches involving this domain","severity":"POSITIVE",
            "evidence":"HIBP returned empty","remediation":"Maintain — set up HIBP domain monitoring for proactive alerts.",
            "cwe":"CWE-200","owasp":"M9:2023"}
BREACH_AGGREGATOR_FINDING_RULES = [rule_f, rule_n]
