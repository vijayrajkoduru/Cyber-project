"""securitytrails_subdomains — findings rules."""
def rule_found(s):
    c = s.get("st_count") or 0
    if c == 0: return None
    return {"name":f"SecurityTrails: {c} subdomain(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("st_sample",""),
            "remediation":"SecurityTrails has the largest passive DNS index. These are historical + current subdomains. Audit each for unintended exposure."}

def rule_no_key(s):
    if s.get("st_status") != "no-key": return None
    return {"name":"SecurityTrails scan skipped — SECURITYTRAILS_API_KEY not configured","severity":"INFO",
            "evidence":"Set env var SECURITYTRAILS_API_KEY (free tier available)",
            "remediation":"Add SecurityTrails API key to docker-compose env to enable this scanner.",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_auth_err(s):
    if s.get("st_status") != "auth-err": return None
    return {"name":"SecurityTrails API key invalid or quota exhausted","severity":"INFO",
            "evidence":"401/403 from SecurityTrails API",
            "remediation":"Check API key + quota at securitytrails.com/app/account",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_none(s):
    if s.get("st_status") != "ok" or (s.get("st_count") or 0) > 0: return None
    return {"name":"No subdomains in SecurityTrails","severity":"POSITIVE",
            "evidence":"SecurityTrails returned empty subdomain list",
            "remediation":"Limited passive-DNS footprint.",
            "cwe":"CWE-200","owasp":"M2:2023"}

SECURITYTRAILS_SUBDOMAINS_FINDING_RULES = [rule_found, rule_no_key, rule_auth_err, rule_none]
