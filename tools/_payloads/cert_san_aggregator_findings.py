"""cert_san_aggregator — findings rules. ⭐ NEW 2024+."""
def rule_found(s):
    if not s.get("cert_san_found"): return None
    return {"name":f"Active certificates: {s.get('total_active_certs',0)} certs, {s.get('own_sans_count',0)} unique subdomains in SANs","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"Top issuer: {s.get('top_issuer','?')} ({s.get('top_issuer_count',0)} certs). Sample SANs: {s.get('own_sans_sample','')}",
            "remediation":"SANs in active certs are the gold-standard subdomain enumeration source. Audit each SAN for unintended exposure (dev/staging certs leaking internal naming)."}

def rule_not_found(s):
    if s.get("cert_san_found"): return None
    return {"name":"No active certificates in CT logs","severity":"INFO",
            "evidence":"crt.sh exclude=expired returned empty",
            "remediation":"Domain may not have current HTTPS certs.",
            "cwe":"CWE-200","owasp":"M2:2023"}

CERT_SAN_AGGREGATOR_FINDING_RULES = [rule_found, rule_not_found]
