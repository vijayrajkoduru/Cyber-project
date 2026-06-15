"""checkov_scanner - findings rules (IaC misconfiguration scan via Checkov).

Each failed Checkov check is a rule-backed misconfiguration (curated policies),
so findings are high-confidence. OSS Checkov often reports severity=UNKNOWN
(severity ships in the platform edition); we grade HIGH when any CRITICAL/HIGH
is present, otherwise MEDIUM.
"""


def rule_no_input(s):
    if not s.get("ckv_no_input"):
        return None
    return {"name": "checkov_scanner: repo_url or local path required",
            "severity": "INFO",
            "evidence": "Checkov needs an IaC source tree (repo_url or local path).",
            "remediation": "Re-run with repo_url=<repo with Terraform/CFN/K8s/Dockerfile> or target=<local IaC dir>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("ckv_error") or ""
    if "checkov binary not installed" not in err:
        return None
    return {"name": "checkov binary not installed",
            "severity": "INFO", "evidence": err,
            "remediation": "Install with `pip install checkov` or add it to the scanner image.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_no_iac(s):
    if not s.get("ckv_no_iac"):
        return None
    return {"name": "No IaC detected (no Terraform / CloudFormation / K8s / Dockerfile / Helm)",
            "severity": "INFO",
            "evidence": "Checkov found no infrastructure-as-code to evaluate in the target.",
            "remediation": "Point checkov at a repo that contains IaC, or ignore if this project has none.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_failed(s):
    failed = s.get("ckv_failed") or 0
    if failed <= 0:
        return None
    sev = s.get("ckv_sev_counts") or {}
    crit, high = sev.get("CRITICAL", 0), sev.get("HIGH", 0)
    med, low, unk = sev.get("MEDIUM", 0), sev.get("LOW", 0), sev.get("UNKNOWN", 0)
    top = s.get("ckv_top") or []
    sample = "; ".join(f"{c['id']} {c['name']} ({c['file']})" for c in top[:4])
    high_band = bool(crit or high)
    return {"name": f"IaC misconfigurations: {failed} failed Checkov check(s)",
            "severity": "HIGH" if high_band else "MEDIUM",
            "cvss": "8.2" if high_band else "5.5",
            "cwe": "CWE-1032", "owasp": "A05:2021",
            "evidence": (f"{failed} failed (C{crit}/H{high}/M{med}/L{low}/?{unk}). " + (sample or "")).strip(),
            "remediation": ("Fix each flagged resource per the Checkov policy "
                            "(https://www.checkov.io/5.Policy%20Index/all.html). Gate CI with "
                            "`checkov -d . --hard-fail-on HIGH`.")}


def rule_clean(s):
    if s.get("ckv_no_input") or s.get("ckv_error") or s.get("ckv_no_iac"):
        return None
    if not s.get("ckv_input_value"):
        return None
    if (s.get("ckv_failed") or 0) > 0:
        return None
    passed = s.get("ckv_passed") or 0
    return {"name": "Checkov clean (no IaC misconfigurations)",
            "severity": "POSITIVE",
            "evidence": f"Checkov passed all {passed} applicable policy check(s) with 0 failures.",
            "remediation": "Keep Checkov in CI; policy packs update regularly.",
            "cwe": "N/A", "owasp": "N/A"}


CHECKOV_SCANNER_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_no_iac,
    rule_failed,
    rule_clean,
]
