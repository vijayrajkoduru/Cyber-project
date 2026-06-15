"""trufflehog_secrets_scan - findings rules (verified secret detection).

A VERIFIED secret is a confirmed live credential (TruffleHog authenticated it),
so it is CRITICAL and effectively zero-FP. Unverified candidates are MEDIUM
(real-looking but not confirmed live — rotate anyway).
"""


def rule_no_input(s):
    if not s.get("th_no_input"):
        return None
    return {"name": "trufflehog_secrets_scan: repo_url or local path required",
            "severity": "INFO",
            "evidence": "TruffleHog needs a source tree (repo_url or local path).",
            "remediation": "Re-run with repo_url=<repo> or target=<local dir>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("th_error") or ""
    if "trufflehog binary not installed" not in err:
        return None
    return {"name": "trufflehog binary not installed",
            "severity": "INFO", "evidence": err,
            "remediation": "Install TruffleHog or add it to the scanner image.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_verified(s):
    n = s.get("th_verified") or 0
    if n <= 0:
        return None
    dets = ", ".join(s.get("th_detectors") or [])
    samples = [x for x in (s.get("th_samples") or []) if x.get("verified")][:4]
    where = "; ".join(f"{x['detector']} @ {x['file']}:{x['line']}" for x in samples)
    return {"name": f"{n} VERIFIED live secret(s) leaked in source",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"TruffleHog authenticated {n} secret(s) as currently LIVE ({dets}). {where}".strip(),
            "remediation": ("ROTATE these credentials immediately — they are confirmed valid and exposed. "
                            "Then purge them from git history (git filter-repo / BFG) and move to a secrets manager.")}


def rule_unverified(s):
    n = s.get("th_unverified") or 0
    if n <= 0:
        return None
    return {"name": f"{n} unverified secret candidate(s) in source",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"TruffleHog flagged {n} high-entropy/secret-shaped value(s) it could not verify as live.",
            "remediation": "Review each; rotate if real. False candidates can be allow-listed in CI."}


def rule_clean(s):
    if s.get("th_no_input") or s.get("th_error") or not s.get("th_ran"):
        return None
    if (s.get("th_verified") or 0) > 0 or (s.get("th_unverified") or 0) > 0:
        return None
    return {"name": "TruffleHog clean (no secrets detected)",
            "severity": "POSITIVE",
            "evidence": "TruffleHog found no verified or candidate secrets in the source tree.",
            "remediation": "Keep secret-scanning in CI (pre-commit + push protection).",
            "cwe": "N/A", "owasp": "N/A"}


TRUFFLEHOG_SECRETS_SCAN_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_verified,
    rule_unverified,
    rule_clean,
]
