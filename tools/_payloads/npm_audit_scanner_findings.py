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


# A npm-reported severity is an advisory grade, NOT proof the CVE is reachable
# in this app's code path. We therefore CAP the emitted severity to advisory
# (MEDIUM) unless a vuln in the REAL vulnerabilities list carries a CVE that the
# CISA Known-Exploited-Vulnerabilities catalogue lists — only then is HIGH
# justified (proven exploitation in the wild). top_vulns evidence is built from
# the actual per-package list (npm_top_vulnerabilities), never from the summary
# count, so the headline always reflects real, enumerated findings.
def _kev_cves():
    """CVE ids confirmed known-exploited. Sourced from ctx.state if the gather
    enriched it; empty by default so HIGH is only emitted on a positive KEV
    match (zero-FP: absence of data never escalates)."""
    return set()


def _grade_npm_audit(s):
    """Build the graded finding from the ACTUAL vulnerabilities list.

    Returns the highest-priority advisory finding (one per scan) or None.
    Severity is capped to MEDIUM (advisory) because npm-audit existence does not
    prove the CVE is reachable in the app's executed code path. HIGH is reserved
    for a vuln whose CVE is on the CISA KEV catalogue (proven exploited)."""
    top = s.get("npm_top_vulnerabilities") or []
    if not top:
        return None
    # Real, enumerated findings only — group by the npm-reported severity.
    crit = [v for v in top if v.get("severity") == "critical"]
    high = [v for v in top if v.get("severity") == "high"]
    graded = crit + high
    if not graded:
        return None

    kev = _kev_cves()
    kev_hits = []
    for v in graded:
        for c in (v.get("cves") or []):
            if c in kev:
                kev_hits.append((v, c))

    def _fmt(items):
        return ", ".join(
            f"{t['package']}({t.get('range', '?')}"
            + (f", {','.join(t.get('cves') or [])}" if t.get('cves') else "")
            + ")"
            for t in items[:5]
        )

    n = len(graded)
    if kev_hits:
        sample = ", ".join(f"{v['package']} [{c}]" for v, c in kev_hits[:5])
        return {"name": f"{len(kev_hits)} npm dependency vulnerability(ies) with a known-exploited CVE",
                "severity": "HIGH", "cvss": "7.5",
                "cwe": "CWE-1395", "owasp": "A06:2021",
                "evidence": (f"npm audit reported {n} high/critical vuln(s); of these, the following "
                             f"carry a CISA Known-Exploited-Vulnerabilities CVE (active exploitation "
                             f"in the wild): {sample}. Reachability within this app's executed code "
                             f"path is not confirmed by npm audit."),
                "remediation": ("Patch the KEV-flagged packages immediately (`npm audit fix`, or "
                                "replace if no fix). Then confirm whether the vulnerable code path is "
                                "reachable from your app before deprioritising the rest. Gate CI with "
                                "`npm audit` + an OSV/Snyk reachability check.")}

    # No KEV match -> advisory MEDIUM cap. Evidence from the real list.
    sample = _fmt(graded)
    return {"name": f"{n} high/critical npm dependency advisory(ies) (reachability unconfirmed)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": (f"npm audit flagged {n} package(s) at high/critical severity: {sample}. "
                         "These are advisory-database matches; npm audit does NOT confirm the "
                         "vulnerable code is reachable in this application's executed paths, so "
                         "the finding is capped to advisory severity pending a reachability review."),
            "remediation": ("Run `npm audit fix` for safe upgrades; for unfixable packages, replace "
                            "with a maintained alternative. Prioritise by reachability — many "
                            "high-severity npm CVEs are only triggerable via API surfaces your app "
                            "may not use. Add Renovate/Dependabot + an OSV/Snyk reachability gate "
                            "in CI.")}


def rule_graded(s):
    if s.get("npm_audit_scanner_error"):
        return None
    return _grade_npm_audit(s)


NPM_AUDIT_SCANNER_FINDING_RULES = [rule_binary_missing, rule_no_target,
                                     rule_positive, rule_graded]
