"""github_org_recon — findings rules."""
def rule_found(s):
    if not s.get("gh_org_found"): return None
    return {"name":f"GitHub org found: {s.get('gh_org_keyword','')} ({s.get('gh_public_repos',0)} repos, {s.get('gh_members',0)} public members)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"name={s.get('gh_org_name','')}, email={s.get('gh_org_email','')}, repos={s.get('gh_top_repos','')}",
            "remediation":"Public GitHub presence = recon goldmine. Audit org repos for: leaked secrets (trufflehog), exposed internal hostnames, deprecated APIs still referenced."}

def rule_not_found(s):
    if s.get("gh_org_found") or s.get("gh_org_status") == "rate-limit": return None
    return {"name":"No GitHub organization matches domain keyword","severity":"INFO",
            "evidence":f"github.com/{s.get('gh_org_keyword','')} returned 404",
            "remediation":"Either no GitHub presence, or org uses different name than domain.",
            "cwe":"CWE-200","owasp":"M2:2023"}

def rule_rate_limit(s):
    if s.get("gh_org_status") != "rate-limit": return None
    return {"name":"GitHub rate-limited","severity":"INFO",
            "evidence":"403 — add GITHUB_TOKEN env var to backend for higher quota",
            "remediation":"Configure a GitHub personal access token in docker-compose.yml backend env.",
            "cwe":"CWE-200","owasp":"M2:2023"}

GITHUB_ORG_RECON_FINDING_RULES = [rule_found, rule_rate_limit, rule_not_found]
