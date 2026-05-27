"""vercel_netlify findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Vercel/Netlify enum requires VERCEL_TOKEN","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add VERCEL_TOKEN to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Vercel/Netlify enum API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
VERCEL_NETLIFY_FINDING_RULES = [rule_no_key, rule_ok]
