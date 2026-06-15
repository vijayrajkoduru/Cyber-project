"""govulncheck_scanner - findings rules (playbook §2 #20).

govulncheck queries the Go vulnerability database (vuln.go.dev / OSV) against a
Go module's dependencies. Matches are curated GO-YYYY-NNNN advisories, so any
match is a confirmed vulnerable Go dependency (zero false positives).
"""


def rule_no_input(s):
    if not s.get("govuln_no_input"):
        return None
    return {"name": "govulncheck_scanner: repo_url or local Go module path required",
            "severity": "INFO",
            "evidence": "govulncheck needs a Go module (go.mod) via repo_url or a local path.",
            "remediation": "Re-run with repo_url=<go repo> or target=<local dir with go.mod>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("govuln_error") or ""
    if "govulncheck binary not installed" not in err:
        return None
    return {"name": "govulncheck binary not installed",
            "severity": "INFO", "evidence": err,
            "remediation": "Install with `go install golang.org/x/vuln/cmd/govulncheck@latest`.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_no_gomod(s):
    if not s.get("govuln_no_gomod"):
        return None
    return {"name": "No go.mod found (not a Go module)",
            "severity": "INFO",
            "evidence": "govulncheck requires a Go module with a committed go.mod. None was found.",
            "remediation": "Point the scan at a Go project root that contains go.mod.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_called(s):
    n = s.get("govuln_called_count") or 0
    if n <= 0:
        return None
    top = s.get("govuln_top") or []
    sample = ", ".join(f"{v['id']} ({v['module']})" for v in top if v.get("called"))[:300]
    return {"name": f"Go: {n} REACHABLE vulnerable dependency(ies)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"govulncheck found {n} vuln(s) whose affected code is actually called by "
                        f"this module (reachable). {sample}",
            "remediation": ("Upgrade the affected modules to the fixed version govulncheck reports "
                            "(see https://pkg.go.dev/vuln/<ID>). Reachable vulns are the priority.")}


def rule_imported(s):
    n = s.get("govuln_imported_count") or 0
    if n <= 0:
        return None
    return {"name": f"Go: {n} vulnerable dependency(ies) present but not reached",
            "severity": "LOW", "cvss": "0.0",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"{n} known-vulnerable Go module(s) are in the dependency graph but their "
                        f"vulnerable symbols are not called. Lower priority, still worth patching.",
            "remediation": "Upgrade when convenient; they become exploitable if your call paths change."}


def rule_clean(s):
    if s.get("govuln_no_input") or s.get("govuln_error") or s.get("govuln_no_gomod"):
        return None
    if not s.get("govuln_input_value"):
        return None
    if (s.get("govuln_called_count") or 0) > 0 or (s.get("govuln_imported_count") or 0) > 0:
        return None
    return {"name": "govulncheck clean (no Go vulnerabilities)",
            "severity": "POSITIVE",
            "evidence": f"govulncheck matched 0 advisories against {s.get('govuln_input_value')}.",
            "remediation": "Keep govulncheck in CI; the Go vuln DB updates continuously.",
            "cwe": "N/A", "owasp": "N/A"}


GOVULNCHECK_SCANNER_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_no_gomod,
    rule_called,
    rule_imported,
    rule_clean,
]
