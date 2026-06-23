"""pip_audit_scanner - findings rules (Python SCA via pip-audit; PYSEC + OSV).

pip-audit matches pinned requirements against curated advisory databases, so a
match is a confirmed vulnerable package (zero false positives).
"""


def rule_no_input(s):
    if not s.get("pip_no_input"):
        return None
    return {"name": "pip_audit_scanner: repo_url or local path required",
            "severity": "INFO",
            "evidence": "pip-audit needs a Python project (requirements*.txt) via repo_url or local path.",
            "remediation": "Re-run with repo_url=<python repo> or target=<local dir with requirements.txt>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("pip_error") or ""
    if "pip-audit binary not installed" not in err:
        return None
    return {"name": "pip-audit binary not installed",
            "severity": "INFO", "evidence": err,
            "remediation": "Install with `pip install pip-audit` or add it to the scanner image.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_no_requirements(s):
    if not s.get("pip_no_requirements"):
        return None
    return {"name": "No requirements.txt found (not a Python project, or deps not pinned)",
            "severity": "INFO",
            "evidence": "pip-audit requires a requirements*.txt; none was found in the target.",
            "remediation": "Export pinned deps (`pip freeze > requirements.txt`, or `poetry export -f requirements.txt`) and commit it so dependencies are auditable.",
            "cwe": "N/A", "owasp": "N/A"}


# CISA Known-Exploited-Vulnerabilities ids confirmed exploited in the wild.
# Empty by default; HIGH is only emitted on a positive KEV match so absence of
# enrichment never escalates severity (zero-FP).
def _kev_ids():
    return set()


def rule_vulns(s):
    n = s.get("pip_vuln_count") or 0
    if n <= 0:
        return None
    top = s.get("pip_top_vulns") or []
    sample = ", ".join(f"{v['id']} ({v['pkg']})" for v in top[:5])
    pkgs = s.get("pip_vuln_pkg_count") or 0
    # pip-audit existence is reliable (curated PYSEC/OSV advisories), but a
    # matched advisory does NOT prove the vulnerable code path is reachable in
    # this application. Cap to advisory severity (MEDIUM); reserve HIGH for a
    # CVE/advisory id on the CISA KEV catalogue (proven exploitation).
    kev = _kev_ids()
    kev_hits = [v for v in top if (v.get("id") or "") in kev]
    if kev_hits:
        ksample = ", ".join(f"{v['id']} ({v['pkg']})" for v in kev_hits[:5])
        return {"name": f"pip-audit: {len(kev_hits)} known-exploited Python advisory(ies)",
                "severity": "HIGH", "cvss": "7.5",
                "cwe": "CWE-1395", "owasp": "A06:2021",
                "evidence": (f"pip-audit matched {n} PYSEC/OSV advisory(ies) across {pkgs} package(s); "
                             f"of these the following are on the CISA Known-Exploited-Vulnerabilities "
                             f"catalogue: {ksample}. Reachability in this app's executed code path is "
                             f"not confirmed by pip-audit."),
                "remediation": ("Patch the KEV-flagged packages immediately to the fix version "
                                "pip-audit reports. Then review reachability for the remaining "
                                "advisories. Gate CI with `pip-audit`.")}
    return {"name": f"pip-audit: {n} vulnerable Python dependency advisory(ies) across {pkgs} package(s)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": (f"pip-audit matched {n} PYSEC/OSV advisory(ies). Top: {sample}. The advisory "
                         "match is reliable, but pip-audit does NOT confirm the vulnerable code is "
                         "reachable in this application's executed paths, so exploitability-in-context "
                         "is unconfirmed and the finding is capped to advisory severity."),
            "remediation": ("Upgrade each package to the fix version pip-audit reports "
                            "(bump requirements.txt / `pip install -U <pkg>`). Prioritise by "
                            "reachability in your code path. Gate CI with `pip-audit`.")}


def rule_clean(s):
    if s.get("pip_no_input") or s.get("pip_error") or s.get("pip_no_requirements"):
        return None
    if not s.get("pip_input_value"):
        return None
    if (s.get("pip_vuln_count") or 0) > 0:
        return None
    deps = s.get("pip_dependency_count") or 0
    return {"name": "pip-audit clean (no known Python advisories)",
            "severity": "POSITIVE",
            "evidence": f"pip-audit found 0 advisories across {deps} dependency(ies).",
            "remediation": "Keep pip-audit in CI; the PyPI/OSV advisory databases update continuously.",
            "cwe": "N/A", "owasp": "N/A"}


PIP_AUDIT_SCANNER_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_no_requirements,
    rule_vulns,
    rule_clean,
]
