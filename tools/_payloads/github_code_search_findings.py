"""github_code_search findings."""

def rule_f(s):
    if s.get("needs_api_key"): return None
    c = s.get("code_hits") or 0
    if c == 0: return None
    return {"name":f"GitHub code search: {c} hit(s) in .env/config files","severity":"HIGH","cvss":"7.5",
            "cwe":"CWE-540","owasp":"M9:2023",
            "evidence":f"Repos: {s.get('repos','')}",
            "remediation":"Manually review each hit. Rotate any leaked secrets immediately. Add pre-commit hooks (trufflehog, gitleaks)."}
def rule_no_key(s):
    if not s.get("needs_api_key"): return None
    return {"name":"GitHub code search requires GITHUB_TOKEN","severity":"INFO",
            "evidence":"Set env var","remediation":"Add GITHUB_TOKEN to enable code-search.",
            "cwe":"CWE-540","owasp":"M9:2023"}
GITHUB_CODE_SEARCH_FINDING_RULES = [rule_f, rule_no_key]
