"""gitlab_bitbucket_scan findings."""

def rule_f(s):
    t = s.get("total") or 0
    if t == 0: return None
    return {"name":f"GitLab/Bitbucket: {t} repo(s) matching keyword","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"GitLab: {s.get('gitlab_count',0)}, Bitbucket: {s.get('bitbucket_count',0)}",
            "remediation":"Public repos may leak secrets (trufflehog scan). Audit each for sensitive data."}
def rule_n(s):
    if (s.get("total") or 0) > 0: return None
    return {"name":"No GitLab/Bitbucket repos matching keyword","severity":"POSITIVE",
            "evidence":"Both APIs returned 0 matches","remediation":"Maintain.",
            "cwe":"CWE-200","owasp":"M2:2023"}
GITLAB_BITBUCKET_SCAN_FINDING_RULES = [rule_f, rule_n]
