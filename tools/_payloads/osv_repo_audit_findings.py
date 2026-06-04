"""osv_repo_audit - findings rules."""


def rule_no_input(s):
    if not s.get("osv_repo_audit_no_input"):
        return None
    return {"name": "osv_repo_audit: image_ref, repo_url, or local path required",
            "severity": "INFO",
            "evidence": "osv-scanner needs an OCI image, git repo URL, or local "
                        "directory (passed as target) to audit dependency manifests.",
            "remediation": "Re-run with one of: image_ref, repo_url, or target=<local dir path>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("osv_repo_audit_error") or ""
    if "osv-scanner binary not installed" not in err:
        return None
    return {"name": "osv-scanner binary not installed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install osv-scanner from https://github.com/google/osv-scanner/releases "
                           "(single Go binary).",
            "cwe": "N/A", "owasp": "N/A"}


def rule_critical(s):
    counts = s.get("osv_severity_counts") or {}
    n = counts.get("CRITICAL", 0)
    if n <= 0:
        return None
    top = [v for v in (s.get("osv_top_vulns") or []) if v["severity"] == "CRITICAL"][:5]
    sample = ", ".join(f"{v['id']} ({v['pkg']}/{v['ecosystem']})" for v in top)
    return {"name": f"OSV.dev: {n} CRITICAL vulnerable dependency(ies)",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"osv-scanner matched {n} CRITICAL OSV record(s). Top: {sample}",
            "remediation": ("Upgrade affected packages to a non-vulnerable version reported by OSV.dev. "
                            "Check https://osv.dev/vulnerability/<ID> for each finding to confirm the "
                            "fixed version. Run osv-scanner in CI with --fail-on=critical to gate merges.")}


def rule_high(s):
    counts = s.get("osv_severity_counts") or {}
    n = counts.get("HIGH", 0)
    if n <= 0:
        return None
    top = [v for v in (s.get("osv_top_vulns") or []) if v["severity"] == "HIGH"][:5]
    sample = ", ".join(f"{v['id']} ({v['pkg']}/{v['ecosystem']})" for v in top)
    return {"name": f"OSV.dev: {n} HIGH vulnerable dependency(ies)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"osv-scanner matched {n} HIGH OSV record(s). Top: {sample}",
            "remediation": "Patch affected packages within 30 days. Use Dependabot / Renovate for automated PRs."}


def rule_medium(s):
    counts = s.get("osv_severity_counts") or {}
    n = counts.get("MEDIUM", 0)
    if n <= 0:
        return None
    return {"name": f"OSV.dev: {n} MEDIUM vulnerable dependency(ies)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"osv-scanner matched {n} MEDIUM OSV record(s).",
            "remediation": "Schedule patching in next maintenance window."}


def rule_ecosystem_spread(s):
    eco = s.get("osv_by_ecosystem") or {}
    if len(eco) < 3:
        return None
    top = ", ".join(f"{k}({v})" for k, v in sorted(eco.items(), key=lambda x: -x[1])[:5])
    return {"name": f"Vulnerable dependencies spread across {len(eco)} ecosystem(s)",
            "severity": "INFO",
            "evidence": f"Top ecosystems: {top}",
            "remediation": "Multi-ecosystem projects need a unified SBOM ingestion (Dependency-Track) "
                           "to track vulns and license posture across npm/pip/go/etc.",
            "cwe": "N/A"}


def rule_clean(s):
    if s.get("osv_repo_audit_no_input") or s.get("osv_repo_audit_error"):
        return None
    if (s.get("osv_total_vulns") or 0) > 0:
        return None
    if not s.get("osv_input_value"):
        return None
    return {"name": "OSV.dev audit clean",
            "severity": "POSITIVE",
            "evidence": f"osv-scanner matched 0 OSV records against {s.get('osv_input_value')}.",
            "remediation": "Continue weekly osv-scanner runs in CI; new OSV records land daily.",
            "cwe": "N/A", "owasp": "N/A"}


OSV_REPO_AUDIT_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_critical,
    rule_high,
    rule_medium,
    rule_ecosystem_spread,
    rule_clean,
]
