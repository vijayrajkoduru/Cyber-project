"""gitleaks_secrets_scan - findings rules."""


def rule_no_input(s):
    if not s.get("gitleaks_secrets_scan_no_input"):
        return None
    return {"name": "gitleaks_secrets_scan: repo_url required",
            "severity": "INFO",
            "evidence": "Gitleaks runs against a cloned git repository - ScanRequest.repo_url was empty.",
            "remediation": "Re-run with repo_url set (e.g. 'https://github.com/org/repo'). "
                           "Use a deploy token if the repo is private.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("gitleaks_secrets_scan_error") or ""
    if "gitleaks binary not installed" not in err:
        return None
    return {"name": "gitleaks binary not installed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install gitleaks v8+ from https://github.com/gitleaks/gitleaks (single binary).",
            "cwe": "N/A", "owasp": "N/A"}


def rule_clone_failed(s):
    err = s.get("gitleaks_secrets_scan_error") or ""
    if not ("git clone" in err or "clone timeout" in err):
        return None
    return {"name": "Repository clone failed before gitleaks could scan",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Confirm repo_url is reachable. For private repos, pre-clone the repo and "
                           "pass a local target path instead.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_secrets_found(s):
    n = s.get("gitleaks_total_leaks") or 0
    if n <= 0:
        return None
    by_rule = s.get("gitleaks_by_rule") or {}
    top_rules = sorted(by_rule.items(), key=lambda x: -x[1])[:4]
    rule_sample = ", ".join(f"{r}({c})" for r, c in top_rules)
    files = list((s.get("gitleaks_by_file") or {}).keys())[:3]
    file_sample = ", ".join(files)
    return {"name": f"{n} secret(s) leaked in source repository",
            "severity": "HIGH", "cvss": "8.6",
            "cwe": "CWE-798", "cwe_name": "Use of Hard-coded Credentials",
            "owasp": "A07:2021",
            "evidence": f"gitleaks matched {n} secret(s) in {s.get('gitleaks_repo_url', '?')}. "
                        f"Top rules: {rule_sample}. Top files: {file_sample}",
            "remediation": ("Each leaked secret must be (1) rotated at the upstream service immediately, "
                            "(2) removed from current source via .env/Vault/AWS-SM, (3) purged from git "
                            "history with `git filter-repo --invert-paths` or BFG. Note: rotation is "
                            "mandatory because git history is public/forkable. Add gitleaks pre-commit "
                            "hook + CI gate to prevent recurrence.")}


def rule_aws_credentials(s):
    by_rule = s.get("gitleaks_by_rule") or {}
    aws_count = sum(v for k, v in by_rule.items() if "aws" in k.lower())
    if aws_count <= 0:
        return None
    return {"name": f"{aws_count} AWS credential leak(s) detected",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"gitleaks AWS rules matched {aws_count} time(s) in {s.get('gitleaks_repo_url', '?')}",
            "remediation": ("URGENT - AWS access keys in public repos are scraped within minutes for "
                            "cryptojacking. Immediately rotate via IAM console, audit CloudTrail for "
                            "unauthorized API calls in the last 30 days, and enable AWS Access Analyzer.")}


def rule_clean(s):
    if s.get("gitleaks_secrets_scan_no_input") or s.get("gitleaks_secrets_scan_error"):
        return None
    if (s.get("gitleaks_total_leaks") or 0) > 0:
        return None
    if not s.get("gitleaks_repo_url"):
        return None
    return {"name": "Repository has no secrets detected by gitleaks",
            "severity": "POSITIVE",
            "evidence": f"gitleaks scanned the working tree of {s.get('gitleaks_repo_url')} and found 0 leaks.",
            "remediation": "Continue running gitleaks as a pre-commit hook and in CI to prevent future leaks.",
            "cwe": "N/A", "owasp": "N/A"}


GITLEAKS_SECRETS_SCAN_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_clone_failed,
    rule_aws_credentials,
    rule_secrets_found,
    rule_clean,
]
