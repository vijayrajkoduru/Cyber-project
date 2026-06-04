"""npm_audit_scanner - findings rules."""


def rule_binary_missing(s):
    if s.get("npm_audit_scanner_error") != "npm binary not installed":
        return None
    return {"name": "npm binary not installed",
            "severity": "INFO",
            "evidence": "shutil.which('npm') returned None",
            "remediation": "Install via: apt-get install nodejs npm.",
            "cwe": "CWE-1006"}


def rule_no_target(s):
    e = s.get("npm_audit_scanner_error") or ""
    if "no scannable target" not in e and "no package.json" not in e:
        return None
    return {"name": "No Node.js project to audit",
            "severity": "INFO",
            "evidence": e,
            "remediation": ("Provide either: a local path containing package.json as ScanRequest.target, "
                            "OR ScanRequest.repo_url to clone a git repo containing a Node.js project."),
            "cwe": "CWE-1006"}


def rule_positive(s):
    if s.get("npm_audit_scanner_total", 0) > 0:
        return None
    if s.get("npm_audit_scanner_error"):
        return None
    vs = s.get("npm_vuln_summary") or {}
    if not vs:
        return None
    return {"name": "npm audit: no critical/high vulnerabilities",
            "severity": "POSITIVE",
            "evidence": (f"Total deps: {s.get('npm_total_dependencies', 0)}; "
                         f"info={vs.get('info', 0)}, low={vs.get('low', 0)}, "
                         f"moderate={vs.get('moderate', 0)}, high=0, critical=0"),
            "remediation": "Continue running npm audit in CI; add Renovate/Dependabot for auto-PRs.",
            "cwe": "CWE-1395"}


def rule_critical(s):
    vs = s.get("npm_vuln_summary") or {}
    crit = vs.get("critical", 0) or 0
    if crit == 0:
        return None
    top = [v for v in (s.get("npm_top_vulnerabilities") or []) if v.get("severity") == "critical"][:5]
    sample = ", ".join(f"{t['package']}({t.get('range', '?')})" for t in top)
    return {"name": f"{crit} CRITICAL npm vulnerabilities",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"Critical packages: {sample}",
            "remediation": ("Run `npm audit fix --force` (review breaking changes first); for any "
                            "package where fix is not available, replace with maintained alternative. "
                            "Add Renovate Bot to auto-PR upgrades. Add `npm audit --audit-level=high` "
                            "as a CI gate to block future merges with new criticals.")}


def rule_high(s):
    vs = s.get("npm_vuln_summary") or {}
    high = vs.get("high", 0) or 0
    if high == 0:
        return None
    top = [v for v in (s.get("npm_top_vulnerabilities") or []) if v.get("severity") == "high"][:5]
    sample = ", ".join(f"{t['package']}({t.get('range', '?')})" for t in top)
    return {"name": f"{high} HIGH-severity npm vulnerabilities",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"High packages: {sample}",
            "remediation": ("Run `npm audit fix` for safe upgrades. Verify each package's CVE: many "
                            "high-severity npm CVEs are only reachable via specific API paths your app "
                            "may not use - prioritize fixes by reachability. Add Snyk/OSV in CI.")}


NPM_AUDIT_SCANNER_FINDING_RULES = [rule_binary_missing, rule_no_target,
                                     rule_positive, rule_critical, rule_high]
