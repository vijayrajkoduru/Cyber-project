"""llm_param_inference findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"LLM parameter inference requires ANTHROPIC_API_KEY","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add ANTHROPIC_API_KEY to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"LLM parameter inference API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
LLM_PARAM_INFERENCE_FINDING_RULES = [rule_no_key, rule_ok]
