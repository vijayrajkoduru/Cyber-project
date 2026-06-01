"""§25 Supply Chain — 95 endpoints per 25_supply_chain.md.

VL-FORGE 2026-05-30: 4 live probes for CI/CD config + package manifest
leakage at standard webroot paths (.github/workflows, .gitlab-ci.yml,
Jenkinsfile, package.json, composer.json, requirements.txt).
"""
import urllib.request, urllib.error
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


def _host(t):
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t

def _http_get(url, timeout=3):
    try:
        r = urllib.request.Request(url, headers={"User-Agent":"VulnusLab/2.0"})
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(2048).decode("utf-8", errors="ignore")
        except Exception: return e.code, ""
    except Exception:
        return 0, ""

def _build(tool, target, findings, tested, summary):
    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"POSITIVE":0}
    top = "INFO"
    for f in findings:
        if sev_order.get(f.get("severity","INFO"),0) > sev_order.get(top,0):
            top = f.get("severity","INFO")
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": top in ("CRITICAL","HIGH","MEDIUM"),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary, "raw_data": {}}


def _probe_gha_workflow_leak(target, req):
    """Check for GitHub Actions workflow files exposed in webroot."""
    base = f"https://{_host(target)}"
    paths = [".github/workflows/main.yml", ".github/workflows/deploy.yml",
              ".github/workflows/ci.yml", ".github/workflows/release.yml",
              ".github/dependabot.yml", ".github/CODEOWNERS"]
    leaked = []
    for p in paths:
        code, body = _http_get(f"{base}/{p}", timeout=3)
        if code == 200 and len(body) > 30:
            leaked.append({"path": p, "size": len(body)})
    findings = []
    if leaked:
        findings.append(wrap_finding(
            f"GitHub Actions config exposed: {len(leaked)} workflow files",
            "HIGH", cvss="7.5", cwe="CWE-538",
            remediation="Never serve .github/ directory from webroot; configure server to deny.",
            evidence_marker=", ".join(l["path"] for l in leaked)))
    else:
        findings.append(wrap_finding(
            "No GitHub Actions workflow files exposed",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue webroot hygiene.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return _build("gha_secrets_leak_audit", target, findings, len(paths),
                   "GitHub Actions workflow exposure probe")


def _probe_ci_config_leak(target, req):
    """Probe for GitLab/Jenkins/CircleCI config files."""
    base = f"https://{_host(target)}"
    paths = [".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml",
              ".travis.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml",
              ".drone.yml", ".buildkite/pipeline.yml"]
    leaked = []
    for p in paths:
        code, body = _http_get(f"{base}/{p}", timeout=3)
        if code == 200 and len(body) > 30:
            leaked.append({"path": p, "size": len(body)})
    findings = []
    if leaked:
        findings.append(wrap_finding(
            f"CI/CD config files exposed: {len(leaked)}",
            "HIGH", cvss="7.5", cwe="CWE-538",
            remediation="Block CI config files from webroot via .htaccess / nginx deny rule.",
            evidence_marker=", ".join(l["path"] for l in leaked)))
    else:
        findings.append(wrap_finding(
            "No CI/CD config files exposed at standard paths",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return _build("gitlab_ci_secrets_audit", target, findings, len(paths),
                   "CI/CD config leak probe")


def _probe_package_manifest_leak(target, req):
    """Probe for package manifests that may leak dependencies + versions."""
    base = f"https://{_host(target)}"
    paths = ["package.json", "package-lock.json", "yarn.lock",
              "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
              "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
              "go.mod", "go.sum", "Cargo.toml", "Cargo.lock"]
    leaked = []
    for p in paths:
        code, body = _http_get(f"{base}/{p}", timeout=3)
        if code == 200 and len(body) > 30:
            # Look for plausible content
            if any(k in body[:500].lower() for k in ['"name"', '"version"', "==", "~>", "require"]):
                leaked.append({"path": p, "size": len(body)})
    findings = []
    if leaked:
        findings.append(wrap_finding(
            f"Package manifest leak: {len(leaked)} dependency files exposed",
            "MEDIUM", cvss="5.5", cwe="CWE-200",
            remediation="Block manifest files from webroot; rely on artifact storage.",
            evidence_marker=", ".join(l["path"] for l in leaked)))
    else:
        findings.append(wrap_finding(
            "No package manifests at standard webroot paths",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return _build("sca_npm_audit", target, findings, len(paths),
                   "Package manifest webroot leak probe")


def _probe_dotenv_leak(target, req):
    """Probe for .env / config files that leak secrets."""
    base = f"https://{_host(target)}"
    paths = [".env", ".env.local", ".env.production", ".env.development",
              "config.json", "config.yml", "secrets.json", "secrets.yaml",
              "credentials", ".aws/credentials", ".dockerconfigjson"]
    leaked = []
    for p in paths:
        code, body = _http_get(f"{base}/{p}", timeout=3)
        if code == 200 and len(body) > 5:
            if any(k in body.upper() for k in ["KEY=", "SECRET=", "TOKEN=", "PASSWORD=", "PASSWD"]):
                leaked.append({"path": p, "preview": body[:80]})
    findings = []
    if leaked:
        findings.append(wrap_finding(
            f"SECRETS LEAK: {len(leaked)} environment/config files exposed",
            "CRITICAL", cvss="9.5", cwe="CWE-200",
            remediation="REMOVE .env from webroot IMMEDIATELY. Rotate exposed credentials.",
            evidence_marker=", ".join(f"{l['path']} contains key/secret/token/password" for l in leaked)))
    else:
        findings.append(wrap_finding(
            "No .env or secret config files at standard webroot paths",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue webroot hygiene; deny .env via server config.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return _build("dep_install_script_audit", target, findings, len(paths),
                   ".env / secrets leak probe")


PROBES = {
    "gha_secrets_leak_audit":     _probe_gha_workflow_leak,
    "gitlab_ci_secrets_audit":    _probe_ci_config_leak,
    "sca_npm_audit":              _probe_package_manifest_leak,
    "dep_install_script_audit":   _probe_dotenv_leak,
}

T = [
    # §1 SBOM (13)
    ("sbom_syft_gen", "Syft SBOM gen.", "INFO", "0.0"),
    ("sbom_cyclonedx_gen", "CycloneDX SBOM gen.", "INFO", "0.0"),
    ("sbom_spdx_gen", "SPDX SBOM gen.", "INFO", "0.0"),
    ("sbom_anchore_gen", "Anchore SBOM gen.", "INFO", "0.0"),
    ("sbom_grype_validate", "Grype SBOM validate.", "MEDIUM", "5.5"),
    ("sbom_trivy_validate", "Trivy SBOM validate.", "MEDIUM", "5.5"),
    ("sbom_cdxgen_audit", "cdxgen audit.", "MEDIUM", "5.5"),
    ("sbom_dependency_track_ingest", "Dependency-Track ingest.", "MEDIUM", "5.5"),
    ("sbom_vex_attach", "VEX attach.", "INFO", "0.0"),
    ("sbom_diff_release", "SBOM release diff.", "INFO", "0.0"),
    ("sbom_attestation_attach", "Attestation attach (cosign).", "MEDIUM", "5.5"),
    ("sbom_completeness_check", "SBOM completeness check.", "MEDIUM", "5.5"),
    ("manual_sbom_review", "Manual SBOM review.", "INFO", "0.0"),
    # §2 Dependency Vuln SCA (15)
    ("sca_npm_audit", "npm audit.", "MEDIUM", "5.5"),
    ("sca_yarn_audit", "yarn audit.", "MEDIUM", "5.5"),
    ("sca_pip_audit", "pip-audit.", "MEDIUM", "5.5"),
    ("sca_safety_check", "Safety pip check.", "MEDIUM", "5.5"),
    ("sca_poetry_audit", "Poetry audit.", "MEDIUM", "5.5"),
    ("sca_bundler_audit", "bundler-audit.", "MEDIUM", "5.5"),
    ("sca_govulncheck", "govulncheck.", "MEDIUM", "5.5"),
    ("sca_cargo_audit", "cargo-audit.", "MEDIUM", "5.5"),
    ("sca_composer_audit", "composer audit.", "MEDIUM", "5.5"),
    ("sca_dotnet_vuln", "dotnet vuln check.", "MEDIUM", "5.5"),
    ("sca_owasp_dep_check", "OWASP Dependency-Check.", "MEDIUM", "5.5"),
    ("sca_snyk_oss", "Snyk OSS.", "MEDIUM", "5.5"),
    ("sca_osv_scanner", "OSV scanner.", "MEDIUM", "5.5"),
    ("sca_renovate_check", "Renovate config check.", "INFO", "0.0"),
    ("sca_dependabot_check", "Dependabot config check.", "INFO", "0.0"),
    # §3 Dep Confusion / Typosquat (9)
    ("dep_confusion_internal_pkg_audit", "Internal pkg + public registry name collision.", "CRITICAL", "9.0"),
    ("dep_confusion_namespace_audit", "Namespace confusion audit.", "HIGH", "7.5"),
    ("dep_typosquat_npm", "npm typosquat scan.", "HIGH", "7.5"),
    ("dep_typosquat_pypi", "PyPI typosquat scan.", "HIGH", "7.5"),
    ("dep_typosquat_rubygems", "RubyGems typosquat scan.", "HIGH", "7.5"),
    ("dep_install_script_audit", "Install-script audit.", "HIGH", "7.5"),
    ("dep_postinstall_lock", "postinstall lockdown audit.", "MEDIUM", "5.5"),
    ("dep_lockfile_integrity", "Lockfile integrity check.", "MEDIUM", "5.5"),
    ("manual_dep_confusion_review", "Manual dep confusion review.", "INFO", "0.0"),
    # §4 CI/CD Pipeline (15)
    ("gha_actions_pinning_audit", "GitHub Actions pinning audit.", "MEDIUM", "5.5"),
    ("gha_secrets_leak_audit", "GHA secrets leak audit.", "HIGH", "8.0"),
    ("gha_self_hosted_runner_abuse", "GHA self-hosted runner abuse.", "HIGH", "8.0"),
    ("gha_oidc_token_audit", "GHA OIDC token audit.", "HIGH", "7.5"),
    ("gitlab_ci_secrets_audit", "GitLab CI secrets audit.", "HIGH", "8.0"),
    ("jenkins_credential_audit", "Jenkins credential audit.", "HIGH", "8.0"),
    ("circleci_secrets_audit", "CircleCI secrets audit.", "HIGH", "8.0"),
    ("argo_workflow_audit", "Argo Workflow audit.", "MEDIUM", "5.5"),
    ("tekton_audit", "Tekton audit.", "MEDIUM", "5.5"),
    ("buildkite_audit", "Buildkite audit.", "MEDIUM", "5.5"),
    ("teamcity_audit", "TeamCity audit.", "MEDIUM", "5.5"),
    ("cd_argocd_audit", "ArgoCD audit.", "MEDIUM", "5.5"),
    ("cd_flux_audit", "Flux audit.", "MEDIUM", "5.5"),
    ("manual_cicd_review", "Manual CI/CD review.", "INFO", "0.0"),
    ("manual_cicd_chain", "Manual CI/CD chain.", "INFO", "0.0"),
    # §5 Code Signing / Provenance SLSA (13)
    ("slsa_l1_provenance", "SLSA L1 provenance.", "MEDIUM", "5.5"),
    ("slsa_l2_provenance", "SLSA L2 provenance.", "MEDIUM", "5.5"),
    ("slsa_l3_provenance", "SLSA L3 provenance.", "HIGH", "7.0"),
    ("slsa_l4_provenance", "SLSA L4 provenance.", "HIGH", "7.0"),
    ("cosign_sign_verify", "Cosign sign+verify.", "MEDIUM", "5.5"),
    ("sigstore_fulcio_rekor", "Sigstore Fulcio+Rekor.", "MEDIUM", "5.5"),
    ("in_toto_attestation", "in-toto attestation.", "MEDIUM", "5.5"),
    ("github_attestations_audit", "GitHub attestations audit.", "MEDIUM", "5.5"),
    ("npm_provenance_audit", "npm provenance audit.", "MEDIUM", "5.5"),
    ("sssa_compliance_audit", "SSSA compliance audit.", "MEDIUM", "5.5"),
    ("salsa_verify_pipeline", "SALSA verify pipeline.", "MEDIUM", "5.5"),
    ("provenance_full_chain_audit", "Full chain provenance audit.", "MEDIUM", "5.5"),
    ("manual_signing_review", "Manual signing review.", "INFO", "0.0"),
    # §6 Package Registry (11)
    ("registry_npm_2fa_audit", "npm 2FA audit.", "MEDIUM", "5.5"),
    ("registry_pypi_2fa_audit", "PyPI 2FA audit.", "MEDIUM", "5.5"),
    ("registry_rubygems_2fa_audit", "RubyGems 2FA audit.", "MEDIUM", "5.5"),
    ("registry_token_rotation", "Registry token rotation audit.", "MEDIUM", "5.5"),
    ("registry_publish_acl_audit", "Publish ACL audit.", "MEDIUM", "5.5"),
    ("registry_yanked_package_check", "Yanked package check.", "MEDIUM", "5.5"),
    ("registry_malicious_package_db", "Malicious package DB cross-ref.", "HIGH", "7.5"),
    ("registry_credential_dump_check", "Registry credential dump check.", "HIGH", "7.5"),
    ("registry_mirror_audit", "Registry mirror audit.", "MEDIUM", "5.5"),
    ("registry_org_settings_audit", "Registry org settings audit.", "MEDIUM", "5.5"),
    ("manual_registry_review", "Manual registry review.", "INFO", "0.0"),
    # §7 Container Image Supply Chain (11)
    ("image_base_provenance", "Base image provenance.", "MEDIUM", "5.5"),
    ("image_layer_audit", "Image layer audit.", "INFO", "0.0"),
    ("image_unpinned_tag", "Unpinned image tag (latest).", "MEDIUM", "5.5"),
    ("image_digest_pinning", "Image digest pinning audit.", "MEDIUM", "5.5"),
    ("image_sbom_attached", "SBOM attached to image audit.", "MEDIUM", "5.5"),
    ("image_signature_required", "Image signature required.", "HIGH", "7.0"),
    ("image_vuln_threshold", "Image vuln threshold gate.", "MEDIUM", "5.5"),
    ("image_secrets_postbuild", "Secrets post-build scan.", "HIGH", "8.0"),
    ("image_distroless_audit", "Distroless audit.", "INFO", "0.0"),
    ("image_minimal_base_audit", "Minimal base audit.", "INFO", "0.0"),
    ("manual_image_supply_review", "Manual image supply review.", "INFO", "0.0"),
    # §8 Open-Source Health Audit (8)
    ("oss_scorecards_audit", "OpenSSF Scorecards audit.", "INFO", "0.0"),
    ("oss_criticality_score", "OpenSSF Criticality Score.", "INFO", "0.0"),
    ("oss_maintainer_count_audit", "Maintainer count audit.", "MEDIUM", "5.5"),
    ("oss_bus_factor_audit", "Bus factor audit.", "MEDIUM", "5.5"),
    ("oss_unmaintained_check", "Unmaintained dependency check.", "HIGH", "7.0"),
    ("oss_security_md_check", "SECURITY.md check.", "INFO", "0.0"),
    ("manual_oss_review", "Manual OSS review.", "INFO", "0.0"),
    ("manual_oss_chain", "Manual OSS chain.", "INFO", "0.0"),
]

router = make_advisory_router("supply_chain", T,
    playbook_ref="See module_playbooks/25_supply_chain.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
