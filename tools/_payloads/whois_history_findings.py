"""whois_history — findings rules."""
def rule_history(s):
    if not s.get("whois_history_found"): return None
    n = s.get("history_count") or 0
    sev = "MEDIUM" if n > 10 else "INFO"
    return {"name":f"WHOIS history shows {n} record change(s)","severity":sev,
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"first={s.get('earliest_year','?')}, last={s.get('latest_year','?')}",
            "remediation":"Frequent ownership/contact changes can indicate domain trading or compromise. Many changes warrant identity verification."}

def rule_no_history(s):
    if s.get("whois_history_found"): return None
    return {"name":"No WHOIS history retrieved","severity":"INFO",
            "evidence":"viewdns.info returned no records",
            "remediation":"Try DomainTools Iris (paid) for deeper history.",
            "cwe":"CWE-200","owasp":"M2:2023"}

WHOIS_HISTORY_FINDING_RULES = [rule_history, rule_no_history]
