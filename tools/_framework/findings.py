"""Findings rules engine — runs a list of rules against scanner state.

Each rule is a plain function:

    def rule_dnssec_disabled(state):
        if (state.get("dnssec") or "").lower() in ("signed","yes"): return None
        if not state.get("dnssec"): return None
        return {"name": "DNSSEC not enabled",
                "severity": "MEDIUM",
                "cwe": "CWE-345",
                "evidence": f"DNSSEC: {state.get('dnssec')} — DNS not cryptographically signed",
                "remediation": "Enable DNSSEC at your registrar."}

Pattern keeps the scanner files small (just data + parsers) and the
rules library small (just declarative logic, no side effects).

Rules NEVER raise — exceptions are caught and the rule is skipped so a
single buggy rule doesn't kill the whole scan.
"""
from tools._shared import wrap_finding
from tools._framework.severity_policy import cap_if_advisory


def run_rules(state: dict, rules: list) -> list:
    """Run a list of finding rules against state.
    Returns a list of wrap_finding() outputs ready for standard_response.

    Each rule receives `state` (dict populated by the scanner's gatherers)
    and returns either None (no finding) or a dict with:
        name        — short title shown in the report (required)
        severity    — CRITICAL / HIGH / MEDIUM / LOW / INFO / POSITIVE (required)
        evidence    — concrete evidence string (optional)
        cwe         — CWE-XXX id (optional)
        remediation — fix guidance (optional)
    """
    findings = []
    for rule in rules:
        try:
            res = rule(state)
        except Exception:
            continue
        if not res:
            continue
        # Global advisory-severity cap: precondition-style "verify your patch"
        # findings get clamped to INFO unless the scanner stamped
        # `verified_exploit: True`. Single seam, no per-scanner edits.
        res = cap_if_advisory(res)
        findings.append(wrap_finding(
            res["name"],
            res["severity"],
            cvss=res.get("cvss", "0.0"),
            cve=res.get("cve", "N/A"),
            cwe=res.get("cwe", "N/A"),
            cwe_name=res.get("cwe_name", ""),
            owasp=res.get("owasp", "N/A"),
            remediation=res.get("remediation", ""),
            evidence_marker=res.get("evidence", ""),
            verified_exploit=res.get("verified_exploit", False),
        ))
    return findings


def severity_counts(findings: list) -> dict:
    """Count findings by severity. Returns {CRITICAL: n, HIGH: n, ...}."""
    counts = {}
    for f in findings:
        s = str(f.get("severity", "INFO")).upper()
        counts[s] = counts.get(s, 0) + 1
    return counts
