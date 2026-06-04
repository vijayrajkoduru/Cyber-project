"""syft_sbom_generate - findings rules. SBOM generation is informational
by design (no vuln matching here - see grype_sbom_scan), so the rules are
mostly INFO + a single POSITIVE for a healthy SBOM."""


def rule_no_input(s):
    if not s.get("syft_sbom_generate_no_input"):
        return None
    return {"name": "syft_sbom_generate: image_ref, repo_url, or local path required",
            "severity": "INFO",
            "evidence": "syft needs an OCI image, git repo URL, or local directory to derive an SBOM.",
            "remediation": "Re-run with one of: image_ref (e.g. 'nginx:1.21'), repo_url, or target=<dir path>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("syft_sbom_generate_error") or ""
    if "syft binary not installed" not in err:
        return None
    return {"name": "syft binary not installed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install syft from https://github.com/anchore/syft (single Go binary).",
            "cwe": "N/A", "owasp": "N/A"}


def rule_failure(s):
    err = s.get("syft_sbom_generate_error") or ""
    if not err or "binary not installed" in err:
        return None
    return {"name": "syft SBOM generation failed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Confirm the image/repo is reachable and `syft scan <target>` succeeds manually.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_sbom_generated(s):
    if not s.get("sbom_artifact_path"):
        return None
    cnt = s.get("sbom_component_count") or 0
    types = s.get("sbom_component_types") or {}
    eco_sample = ", ".join(f"{k}({v})" for k, v in list(types.items())[:5])
    return {"name": f"SBOM generated: {cnt} components across {len(types)} ecosystem(s)",
            "severity": "INFO",
            "evidence": (f"Format: {s.get('sbom_format', '?')} "
                         f"spec={s.get('sbom_spec_version', '?')}. "
                         f"Top ecosystems: {eco_sample}. "
                         f"Artifact: {s.get('sbom_artifact_path')} "
                         f"({s.get('sbom_artifact_bytes', 0)} bytes)"),
            "remediation": ("Sign the SBOM with `cosign attest --type cyclonedx --predicate <path> "
                            "<image>` and publish to a Rekor transparency log. Ingest into "
                            "Dependency-Track or Snyk for ongoing vuln + license monitoring. "
                            "EU CRA + US EO 14028 require every shipped artifact to have a "
                            "transferable SBOM."),
            "cwe": "N/A", "owasp": "N/A"}


def rule_thin_sbom(s):
    cnt = s.get("sbom_component_count") or 0
    if cnt <= 0 or cnt > 5:
        return None
    if not s.get("sbom_artifact_path"):
        return None
    return {"name": f"SBOM has only {cnt} component(s) - likely incomplete",
            "severity": "LOW", "cvss": "3.1",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"syft detected only {cnt} component(s) - real production images typically "
                        f"have 50-500+ components. The input may be a stripped image (distroless OK) "
                        f"or syft missed the package manager metadata.",
            "remediation": ("If the image is intentionally distroless this is healthy. Otherwise verify "
                            "syft can read your package manager files - run `syft <target> -vv` to debug "
                            "missing cataloger output.")}


SYFT_SBOM_GENERATE_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_failure,
    rule_sbom_generated,
    rule_thin_sbom,
]
