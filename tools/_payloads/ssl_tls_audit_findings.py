"""ssl_tls_audit findings."""

def rule_weak(s):
    if not s.get("weak_tls"): return None
    return {"name":f"Weak TLS version: {s.get('tls_version','?')}","severity":"HIGH","cvss":"7.4",
            "cwe":"CWE-326","owasp":"M5:2023",
            "evidence":f"Negotiated: {s.get('tls_version','')}",
            "remediation":"Disable SSLv3/TLS1.0/TLS1.1. Enable TLS1.2+ only."}
def rule_good(s):
    if s.get("weak_tls") or not s.get("port_open"): return None
    return {"name":f"TLS {s.get('tls_version','?')} — strong","severity":"POSITIVE",
            "evidence":f"Cert: {s.get('cert_subject','')} issued by {s.get('cert_issuer','')}, exp {s.get('cert_expiry','')}",
            "remediation":"Maintain — modern TLS in use.",
            "cwe":"CWE-326","owasp":"M5:2023"}
def rule_closed(s):
    if s.get("port_open"): return None
    return {"name":"Port 443 not reachable","severity":"INFO",
            "evidence":"HTTPS not available","remediation":"If a web service is intended, expose HTTPS.",
            "cwe":"CWE-200","owasp":"M5:2023"}
SSL_TLS_AUDIT_FINDING_RULES = [rule_weak, rule_good, rule_closed]
