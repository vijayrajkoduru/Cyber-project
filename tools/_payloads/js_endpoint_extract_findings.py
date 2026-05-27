"""js_endpoint_extract findings."""

def rule_f(s):
    c = s.get("js_endpoint_count") or 0
    if c == 0: return None
    return {"name":f"JS bundle reveals {c} API endpoint(s)","severity":"INFO",
            "cwe":"CWE-540","owasp":"M2:2023",
            "evidence":s.get("js_endpoint_sample",""),
            "remediation":"Bundle minification reduces leakage but URLs remain visible. Audit each endpoint for unauthenticated exposure + IDOR/BOLA."}
def rule_n(s):
    if (s.get("js_endpoint_count") or 0) > 0: return None
    return {"name":"No API endpoints found in JS bundles","severity":"POSITIVE",
            "evidence":"Static JS files contain no API path patterns","remediation":"Either SPA-less or well-obfuscated.",
            "cwe":"CWE-540","owasp":"M2:2023"}
JS_ENDPOINT_EXTRACT_FINDING_RULES = [rule_f, rule_n]
