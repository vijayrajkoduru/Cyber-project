"""license_compliance_audit - findings rules (playbook §1 #6).

Turns the syft-json license rollup in ctx.state into compliance findings.
Severity reflects DISTRIBUTION/LEGAL risk, not a security vuln:
  - AGPL  -> HIGH    (network copyleft: SaaS use can trigger source-disclosure)
  - GPL   -> MEDIUM  (strong copyleft: linking/distribution obligations)
  - LGPL/MPL/EPL/CDDL -> LOW (weak/file-level copyleft)
  - unknown/missing -> INFO (compliance gap, not a breach)
All advisory-grade; zero false positives (driven by actual SPDX values).
"""


def rule_no_input(s):
    if not s.get("license_no_input"):
        return None
    return {"name": "license_compliance_audit: image_ref, repo_url, or local path required",
            "severity": "INFO",
            "evidence": "Syft needs an OCI image, git repo URL, or local directory to enumerate "
                        "component licenses.",
            "remediation": "Re-run with one of: image_ref, repo_url, or target=<local dir path>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("license_error") or ""
    if "syft binary not installed" not in err:
        return None
    return {"name": "syft binary not installed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install syft from https://github.com/anchore/syft/releases (single Go binary).",
            "cwe": "N/A", "owasp": "N/A"}


def rule_agpl(s):
    lic = s.get("license_categories") or {}
    hits = lic.get("network_copyleft") or []
    if not hits:
        return None
    sample = ", ".join(f"{h['pkg']} ({h['license']})" for h in hits[:6])
    return {"name": f"Network-copyleft (AGPL) dependency: {len(hits)} component(s)",
            "severity": "LOW", "cvss": "0.0",
            "cwe": "CWE-1104", "owasp": "N/A",
            "evidence": f"AGPL-family licences detected. Offering an AGPL component over a network "
                        f"(SaaS) can trigger a source-disclosure obligation. This is a distribution/"
                        f"legal-compliance signal (advisory), not an exploitable vulnerability. "
                        f"Components: {sample}",
            "remediation": ("Confirm with legal whether AGPL obligations apply to your SaaS distribution. "
                            "Replace with a permissively-licensed equivalent or obtain a commercial licence. "
                            "Track licences in your SBOM (CycloneDX 'licenses' field).")}


def rule_strong_copyleft(s):
    lic = s.get("license_categories") or {}
    hits = lic.get("strong_copyleft") or []
    if not hits:
        return None
    sample = ", ".join(f"{h['pkg']} ({h['license']})" for h in hits[:6])
    return {"name": f"Strong-copyleft (GPL) dependency: {len(hits)} component(s)",
            "severity": "INFO", "cvss": "0.0",
            "cwe": "CWE-1104", "owasp": "N/A",
            "evidence": f"GPL-family licences detected. Linking/redistributing may impose copyleft "
                        f"obligations on your codebase. This is a distribution/legal-compliance "
                        f"signal (advisory), not an exploitable vulnerability. Components: {sample}",
            "remediation": ("Review distribution model with legal. For proprietary products, isolate or "
                            "replace GPL components. Maintain an approved-licence allowlist enforced in CI.")}


def rule_weak_copyleft(s):
    lic = s.get("license_categories") or {}
    hits = lic.get("weak_copyleft") or []
    if not hits:
        return None
    return {"name": f"Weak-copyleft (LGPL/MPL/EPL) dependency: {len(hits)} component(s)",
            "severity": "LOW", "cvss": "0.0",
            "cwe": "CWE-1104", "owasp": "N/A",
            "evidence": f"{len(hits)} component(s) under file-level/weak copyleft. Generally compatible "
                        f"with proprietary use if the component is unmodified and dynamically linked.",
            "remediation": "Document usage; avoid modifying these components without legal review."}


def rule_unknown(s):
    n = s.get("license_unknown_count") or 0
    total = s.get("license_total_components") or 0
    if n <= 0 or total <= 0:
        return None
    pct = round(100.0 * n / total, 1)
    sev = "INFO" if pct < 25 else "LOW"
    return {"name": f"Components with no/unknown licence: {n}/{total} ({pct}%)",
            "severity": sev, "cvss": "0.0",
            "cwe": "CWE-1104", "owasp": "N/A",
            "evidence": f"{n} of {total} components have no declared SPDX licence. Unknown licences "
                        f"are a compliance blind spot (EU CRA / SSDF require licence provenance).",
            "remediation": ("Resolve unknown licences via scancode/fossology deep scan or by contacting "
                            "the upstream project. Fail CI when licence coverage drops below a threshold.")}


def rule_clean(s):
    if s.get("license_no_input") or s.get("license_error"):
        return None
    if not s.get("license_input_value"):
        return None
    lic = s.get("license_categories") or {}
    if (lic.get("network_copyleft") or lic.get("strong_copyleft")
            or lic.get("weak_copyleft") or (s.get("license_unknown_count") or 0) > 0):
        return None
    total = s.get("license_total_components") or 0
    return {"name": "Licence compliance clean (all permissive, fully declared)",
            "severity": "POSITIVE",
            "evidence": f"All {total} components carry permissive, fully-declared licences "
                        f"(MIT/Apache/BSD-class). No copyleft or unknown-licence exposure.",
            "remediation": "Keep an approved-licence allowlist gate in CI to preserve this posture.",
            "cwe": "N/A", "owasp": "N/A"}


LICENSE_COMPLIANCE_AUDIT_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_agpl,
    rule_strong_copyleft,
    rule_weak_copyleft,
    rule_unknown,
    rule_clean,
]
