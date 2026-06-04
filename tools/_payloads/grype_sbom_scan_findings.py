"""grype_sbom_scan - findings rules."""


def rule_no_input(s):
    if not s.get("grype_sbom_scan_no_input"):
        return None
    return {"name": "grype_sbom_scan: image_ref or repo_url required",
            "severity": "INFO",
            "evidence": "Neither ScanRequest.image_ref nor ScanRequest.repo_url was provided. "
                        "Grype needs an OCI image or git repo URL to derive an SBOM.",
            "remediation": "Re-run with image_ref (e.g. 'nginx:1.21') or repo_url "
                           "(e.g. 'https://github.com/org/repo').",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("grype_sbom_scan_error") or ""
    if not ("syft binary not installed" in err or "grype binary not installed" in err):
        return None
    return {"name": "syft/grype binary not installed on scanner host",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install syft + grype from https://github.com/anchore (single-binary installs).",
            "cwe": "N/A", "owasp": "N/A"}


def rule_critical(s):
    counts = s.get("grype_severity_counts") or {}
    n = counts.get("CRITICAL", 0)
    if n <= 0:
        return None
    top = [c for c in (s.get("grype_top_cves") or []) if c["severity"] == "CRITICAL"][:5]
    sample = ", ".join(f"{c['id']} ({c['pkg']}@{c['installed']})" for c in top)
    return {"name": f"SBOM scan: {n} CRITICAL CVE(s) detected by Grype",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"Grype matched {n} CRITICAL vuln(s) in SBOM of {s.get('grype_input_value', '?')}. "
                        f"Top: {sample}",
            "remediation": ("Upgrade affected packages to the FixedVersion immediately - CRITICAL CVEs "
                            "typically have public PoCs within 7 days. If the affected package is a "
                            "transitive dependency, use npm-force-resolutions / pip constraints / "
                            "Maven dependencyManagement to pin the patched version.")}


def rule_high(s):
    counts = s.get("grype_severity_counts") or {}
    n = counts.get("HIGH", 0)
    if n <= 0:
        return None
    top = [c for c in (s.get("grype_top_cves") or []) if c["severity"] == "HIGH"][:5]
    sample = ", ".join(f"{c['id']} ({c['pkg']}@{c['installed']})" for c in top)
    return {"name": f"SBOM scan: {n} HIGH CVE(s) detected by Grype",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"Grype matched {n} HIGH vuln(s) in SBOM of {s.get('grype_input_value', '?')}. "
                        f"Top: {sample}",
            "remediation": ("Patch within 30 days per NIST SSDF guidance. Run `grype --fail-on high` in "
                            "CI to break the build on any new HIGH dependency vuln.")}


def rule_medium(s):
    counts = s.get("grype_severity_counts") or {}
    n = counts.get("MEDIUM", 0)
    if n <= 0:
        return None
    return {"name": f"SBOM scan: {n} MEDIUM CVE(s) detected by Grype",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"Grype matched {n} MEDIUM vuln(s) in SBOM of {s.get('grype_input_value', '?')}.",
            "remediation": "Bulk patch in the next quarterly maintenance window."}


def rule_clean(s):
    if s.get("grype_sbom_scan_no_input") or s.get("grype_sbom_scan_error"):
        return None
    counts = s.get("grype_severity_counts") or {}
    if sum(counts.values()) > 0:
        return None
    if not s.get("grype_input_value"):
        return None
    return {"name": "SBOM scan clean (Grype)",
            "severity": "POSITIVE",
            "evidence": f"Grype matched 0 CVEs against the SBOM derived from "
                        f"{s.get('grype_input_value')}.",
            "remediation": "Continue monthly SBOM scans - new CVEs land in the NVD daily.",
            "cwe": "N/A", "owasp": "N/A"}


GRYPE_SBOM_SCAN_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_critical,
    rule_high,
    rule_medium,
    rule_clean,
]
