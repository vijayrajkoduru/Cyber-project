"""trivy_image_scan - findings rules."""


def rule_no_input(s):
    if not s.get("trivy_image_scan_no_input"):
        return None
    return {"name": "trivy_image_scan: image_ref required",
            "severity": "INFO",
            "evidence": "ScanRequest.image_ref was empty. Pass an OCI image reference "
                        "(e.g. 'nginx:1.21' or 'gcr.io/distroless/base') to enable Trivy CVE scanning.",
            "remediation": "Re-run the scan with the customer's production image tag set as image_ref.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("trivy_image_scan_error") or ""
    if "trivy binary not installed" not in err:
        return None
    return {"name": "Trivy binary not installed on scanner host",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install Trivy via `apt-get install trivy` or pull the official aquasec/trivy image.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_critical(s):
    counts = s.get("trivy_severity_counts") or {}
    n = counts.get("CRITICAL", 0)
    if n <= 0:
        return None
    top = [c for c in (s.get("trivy_top_cves") or []) if c["severity"] == "CRITICAL"][:5]
    sample = ", ".join(f"{c['id']} ({c['pkg']}@{c['installed']})" for c in top)
    return {"name": f"Container image has {n} CRITICAL CVE(s)",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"Image {s.get('trivy_image_ref', '?')} - Trivy reports {n} CRITICAL CVE(s). "
                        f"Top: {sample}",
            "remediation": ("Rebuild the image with patched base layer (FROM alpine:3.20 -> alpine:3.21 etc) "
                            "or pin to upstream FixedVersion for each affected package. Re-scan after every "
                            "rebuild. Consider Trivy admission policy in K8s to block CRITICAL CVEs at deploy time.")}


def rule_high(s):
    counts = s.get("trivy_severity_counts") or {}
    n = counts.get("HIGH", 0)
    if n <= 0:
        return None
    top = [c for c in (s.get("trivy_top_cves") or []) if c["severity"] == "HIGH"][:5]
    sample = ", ".join(f"{c['id']} ({c['pkg']}@{c['installed']})" for c in top)
    return {"name": f"Container image has {n} HIGH CVE(s)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"Image {s.get('trivy_image_ref', '?')} - Trivy reports {n} HIGH CVE(s). "
                        f"Top: {sample}",
            "remediation": ("Patch affected packages to FixedVersion. For OS packages run `apk upgrade` / "
                            "`apt-get upgrade` in the Dockerfile build stage and re-publish the image. "
                            "If no fix exists, evaluate VEX (Vulnerability Exploitability Exchange) "
                            "to mark the CVE not_affected.")}


def rule_medium(s):
    counts = s.get("trivy_severity_counts") or {}
    n = counts.get("MEDIUM", 0)
    if n <= 0:
        return None
    return {"name": f"Container image has {n} MEDIUM CVE(s)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"Image {s.get('trivy_image_ref', '?')} - Trivy reports {n} MEDIUM CVE(s).",
            "remediation": ("Schedule patching in next maintenance window. Track via Dependency-Track "
                            "or similar SBOM inventory.")}


def rule_clean(s):
    if s.get("trivy_image_scan_no_input") or s.get("trivy_image_scan_error"):
        return None
    counts = s.get("trivy_severity_counts") or {}
    if sum(counts.values()) > 0:
        return None
    if not s.get("trivy_image_ref"):
        return None
    return {"name": "Container image is free of known CVEs (Trivy)",
            "severity": "POSITIVE",
            "evidence": f"Trivy scan of {s.get('trivy_image_ref')} returned 0 vulnerabilities "
                        f"across CRITICAL/HIGH/MEDIUM/LOW severities.",
            "remediation": "Re-scan quarterly - new CVEs are disclosed for popular base images weekly.",
            "cwe": "N/A", "owasp": "N/A"}


TRIVY_IMAGE_SCAN_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_critical,
    rule_high,
    rule_medium,
    rule_clean,
]
