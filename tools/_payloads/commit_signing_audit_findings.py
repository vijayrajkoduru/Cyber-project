"""commit_signing_audit - findings rules (playbook §5 #70).

Measures what fraction of recent commits carry a cryptographic signature.
Validity (good vs bad key) cannot be judged without the signers' public keys,
so the signal is signed-vs-unsigned presence. Unsigned history means commits
cannot be attributed -> a supply-chain integrity gap (SLSA / SSDF).
"""


def rule_no_input(s):
    if not s.get("sign_no_input"):
        return None
    return {"name": "commit_signing_audit: repo_url required",
            "severity": "INFO",
            "evidence": "Needs a git repository URL (with history) to inspect commit signatures.",
            "remediation": "Re-run with repo_url=<git repo>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_error(s):
    err = s.get("sign_error") or ""
    if not err:
        return None
    return {"name": "commit_signing_audit could not inspect history",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Ensure the repository is reachable and contains commit history.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_unsigned(s):
    total = s.get("sign_total") or 0
    signed = s.get("sign_signed") or 0
    if total <= 0 or signed > 0:
        return None
    return {"name": "No commit signing (0% of recent commits signed)",
            "severity": "MEDIUM", "cvss": "0.0",
            "cwe": "CWE-347", "owasp": "A08:2021",
            "evidence": f"0 of the last {total} commits carry a signature. Commits cannot be "
                        f"cryptographically attributed, so a compromised account or pushed-from "
                        f"impersonation is indistinguishable from a legitimate commit.",
            "remediation": ("Enable commit signing (GPG/SSH/Sigstore gitsign) and require it via branch "
                            "protection 'Require signed commits'. SLSA + NIST SSDF expect signed provenance.")}


def rule_partial(s):
    total = s.get("sign_total") or 0
    signed = s.get("sign_signed") or 0
    if total <= 0 or signed <= 0 or signed >= total:
        return None
    pct = round(100.0 * signed / total, 1)
    return {"name": f"Partial commit signing ({pct}% of recent commits signed)",
            "severity": "LOW", "cvss": "0.0",
            "cwe": "CWE-347", "owasp": "A08:2021",
            "evidence": f"{signed} of the last {total} commits are signed ({pct}%). Inconsistent signing "
                        f"means some commits remain unattributable.",
            "remediation": "Enforce 'Require signed commits' branch protection so 100% of merged commits are signed."}


def rule_all_signed(s):
    total = s.get("sign_total") or 0
    signed = s.get("sign_signed") or 0
    if total <= 0 or signed < total:
        return None
    return {"name": f"All recent commits signed ({total}/{total})",
            "severity": "POSITIVE",
            "evidence": f"All of the last {total} commits carry a signature (validity not verified — "
                        f"signer public keys are not available to the scanner).",
            "remediation": "Keep 'Require signed commits' enforced; rotate/verify signer keys periodically.",
            "cwe": "N/A", "owasp": "N/A"}


COMMIT_SIGNING_AUDIT_FINDING_RULES = [
    rule_no_input,
    rule_error,
    rule_unsigned,
    rule_partial,
    rule_all_signed,
]
