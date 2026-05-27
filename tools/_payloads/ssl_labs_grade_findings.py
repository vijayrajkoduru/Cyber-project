"""ssl_labs_grade findings."""

def rule_grade(s):
    g = s.get("grade","")
    if not g or "PENDING" in g: return None
    sev = "POSITIVE" if g.startswith("A") else "HIGH" if g.startswith("F") else "MEDIUM"
    return {"name":f"SSL Labs grade: {g}","severity":sev,"cvss":"6.5" if sev=="HIGH" else ("4.3" if sev=="MEDIUM" else ""),
            "cwe":"CWE-326","owasp":"M5:2023",
            "evidence":f"All endpoints: {s.get('grades_all',g)}",
            "remediation":"Aim for A or A+. Disable TLS 1.0/1.1, weak ciphers, support TLS 1.3."}
def rule_pending(s):
    g = s.get("grade","")
    if not ("PENDING" in g): return None
    return {"name":"SSL Labs scan pending — retry","severity":"INFO",
            "evidence":g,"remediation":"Re-run in 2 minutes (SSL Labs needs time to scan).",
            "cwe":"CWE-200","owasp":"M5:2023"}
SSL_LABS_GRADE_FINDING_RULES = [rule_grade, rule_pending]
