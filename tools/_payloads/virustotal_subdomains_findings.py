"""virustotal_subdomains — findings rules."""
def rule_found(s):
    c = s.get("vt_count") or 0
    if c == 0: return None
    return {"name":f"VirusTotal: {c} subdomain(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("vt_sample",""),
            "remediation":"VT-known subdomains were observed via DNS resolutions or URL submissions. Audit for over-exposure."}

def rule_no_key(s):
    if s.get("vt_status") != "no-key": return None
    return {"name":"VirusTotal scan skipped — VIRUSTOTAL_API_KEY not configured","severity":"INFO",
            "evidence":"Set env var VIRUSTOTAL_API_KEY (free tier: vt.com/gui/join-us)",
            "remediation":"Add VT API key to docker-compose env to enable this scanner.",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_auth_err(s):
    if s.get("vt_status") != "auth-err": return None
    return {"name":"VirusTotal API key invalid or quota exhausted","severity":"INFO",
            "evidence":"401/403 from VT API",
            "remediation":"Check VT API key + quota at vt.com/gui/user/<your>/apikey",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_none(s):
    if s.get("vt_status") != "ok" or (s.get("vt_count") or 0) > 0: return None
    return {"name":"No subdomains known to VirusTotal","severity":"POSITIVE",
            "evidence":"VT returned empty subdomain list",
            "remediation":"Limited passive-intel footprint.",
            "cwe":"CWE-200","owasp":"M2:2023"}

VIRUSTOTAL_SUBDOMAINS_FINDING_RULES = [rule_found, rule_no_key, rule_auth_err, rule_none]
