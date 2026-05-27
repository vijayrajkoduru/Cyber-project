"""favicon_hash — findings rules."""
def rule_found(s):
    if not s.get("favicon_found"): return None
    h = s.get("favicon_mmh3")
    return {"name":"Favicon fingerprint extracted","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"mmh3={h}, size={s.get('favicon_size',0)}B, scheme={s.get('favicon_scheme','?')}",
            "remediation":(f"Pivot: search Shodan with `http.favicon.hash:{h}` to find other servers with the same favicon "
                          "(often reveals related infra). Favicon-fingerprinting is also used by attackers to identify common stacks.") if h else "Favicon found but mmh3 library not installed. `pip install mmh3` for hash + Shodan pivot."}

def rule_not_found(s):
    if s.get("favicon_found"): return None
    return {"name":"No favicon found","severity":"INFO",
            "evidence":"/favicon.ico returned non-200 or empty body",
            "remediation":"Reduces fingerprinting attack surface.",
            "cwe":"CWE-200","owasp":"M2:2023"}

FAVICON_HASH_FINDING_RULES = [rule_found, rule_not_found]
