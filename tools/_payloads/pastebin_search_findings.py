"""pastebin_search — findings rules."""
def rule_found(s):
    c = s.get("pb_count") or 0
    if c == 0: return None
    sev = "HIGH" if c > 10 else "MEDIUM" if c > 3 else "LOW"
    return {"name":f"Domain found in {c} paste(s) on Pastebin","severity":sev,"cvss":"6.0" if sev=="HIGH" else "4.3",
            "cwe":"CWE-200","owasp":"M9:2023",
            "evidence":s.get("pb_sample",""),
            "remediation":"Pastes often contain leaked credentials, source code, or sensitive config. Manually review each paste at psbdmp.ws to identify what was leaked."}

def rule_none(s):
    if (s.get("pb_count") or 0) > 0: return None
    return {"name":"No paste-site hits for this domain","severity":"POSITIVE",
            "evidence":"psbdmp.ws returned 0 results",
            "remediation":"No public paste leakage detected.",
            "cwe":"CWE-200","owasp":"M9:2023"}

PASTEBIN_SEARCH_FINDING_RULES = [rule_found, rule_none]
