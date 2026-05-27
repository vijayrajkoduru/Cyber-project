"""github_subdomains — findings rules."""
def rule_found(s):
    c = s.get("gh_count") or 0
    if c == 0: return None
    return {"name":f"GitHub code search: {c} subdomain(s) found in public code","severity":"MEDIUM","cvss":"4.3",
            "cwe":"CWE-540","owasp":"M9:2023",
            "evidence":s.get("gh_sample",""),
            "remediation":"Subdomains in public GitHub repos = potential credential/config leak. Search GitHub for additional secrets near each subdomain mention."}

def rule_no_token(s):
    if s.get("gh_status") != "no-token": return None
    return {"name":"GitHub code search skipped — GITHUB_TOKEN not configured","severity":"INFO",
            "evidence":"Set GITHUB_TOKEN env var on backend to enable code search.",
            "remediation":"Add a GitHub personal access token to docker-compose env to enable this scanner. Without auth, GitHub blocks /search/code entirely.",
            "cwe":"CWE-540","owasp":"M9:2023"}

def rule_rate_limit(s):
    if s.get("gh_status") != "rate-limit": return None
    return {"name":"GitHub rate-limited","severity":"INFO",
            "evidence":"403 from GitHub API — retry later",
            "remediation":"Wait for rate-limit window to reset.",
            "cwe":"CWE-540","owasp":"M9:2023"}

def rule_none(s):
    if s.get("gh_status") != "ok" or (s.get("gh_count") or 0) > 0: return None
    return {"name":"No subdomains leaked in GitHub code","severity":"POSITIVE",
            "evidence":"GitHub code search returned no domain matches",
            "remediation":"Maintain — no public code leakage of subdomains.",
            "cwe":"CWE-540","owasp":"M9:2023"}

GITHUB_SUBDOMAINS_FINDING_RULES = [rule_found, rule_no_token, rule_rate_limit, rule_none]
