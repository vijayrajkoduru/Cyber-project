"""advisory_techniques - honest advisory-by-design supply-chain checks.

One POST endpoint per playbook technique that genuinely cannot be live-probed
from an external SaaS scanner (needs signing-key custody, registry org-admin
API tokens, cluster kubeconfig, on-host build introspection, or analyst
judgement). Every endpoint returns INFO with an [ADVISORY-BY-DESIGN] marker
via _advisory_by_design_response — vulnerable:false, severity INFO, never a
graded finding. This keeps the module honest: techniques we cannot remotely
verify are surfaced as guidance, not fabricated CRITICAL/HIGH findings.

Covers (per module_playbooks/25_supply_chain.md):
  §1  SBOM signing / Rekor transparency / VEX             (key custody, log access)
  §4  OIDC->cloud trust / branch protection / PWN-request (repo-admin / CI creds)
  §5  SLSA provenance / cosign verify / in-toto / repro   (build artifact custody)
  §6  npm/PyPI 2FA enforcement / install-script behavior   (registry org-admin API)
  §7  image pull-policy / registry mirror / policy ctrl    (cluster kubeconfig)
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._pack_common import _advisory_by_design_response

router = APIRouter()


# (slug, human title, why-it-cannot-be-saas-probed reason)
_ADVISORY_TECHNIQUES = [
    # ── §1 SBOM signing / transparency / VEX ──
    ("sbom_signing_attest",
     "SBOM signing via cosign attest (playbook §1 #9)",
     "Requires custody of the project's Sigstore/cosign signing identity and the "
     "registry artifact to attach the attestation to — not observable externally."),
    ("sbom_rekor_transparency",
     "SBOM Rekor transparency-log inclusion (playbook §1 #10)",
     "Confirming a specific SBOM's Rekor inclusion needs the artifact digest and "
     "signer identity from the build; a SaaS host scan cannot derive these."),
    ("sbom_vex_audit",
     "VEX (Vulnerability Exploitability eXchange) audit (playbook §1 #11)",
     "VEX statements are produced by the vendor's PSIRT against internal triage data; "
     "they cannot be read or validated from an external host probe."),

    # ── §4 CI/CD privileged surfaces ──
    ("gha_oidc_cloud_trust",
     "GitHub Actions OIDC -> cloud trust audit (playbook §4 #46)",
     "Auditing the OIDC trust policy requires read access to the cloud IAM role "
     "trust documents and the repo's workflow permissions — both privileged."),
    ("branch_protection_audit",
     "Branch protection / required-reviews bypass audit (playbook §4 #55)",
     "Branch-protection rules are only visible to repo admins via authenticated "
     "GitHub/GitLab APIs; not exposed to anonymous external scanning."),
    ("pwn_request_audit",
     "Poisoned pull_request_target (PWN-request) detection (playbook §4 #58)",
     "Detecting an exploitable pull_request_target workflow requires reading the "
     "workflow YAML and secret scoping, which needs repo read access."),
    ("self_hosted_runner_audit",
     "Self-hosted runner exposure audit (playbook §4 #45)",
     "Enumerating self-hosted runners requires authenticated GitHub Actions admin "
     "API access; an external host scan cannot see runner registration state."),

    # ── §5 Code-signing & provenance (SLSA) ──
    ("slsa_provenance_verify",
     "SLSA v1.0 build provenance verification (playbook §5 #59)",
     "slsa-verifier needs the released artifact plus its provenance attestation and "
     "the expected builder identity — supplied by the build owner, not a host scan."),
    ("cosign_signature_verify",
     "Sigstore / cosign signature verification (playbook §5 #60)",
     "cosign verify requires the exact image digest and the trusted certificate "
     "identity/issuer policy; these come from the release process, not remote probing."),
    ("intoto_attestation_validate",
     "in-toto attestation validation (playbook §5 #63)",
     "in-toto layout + link metadata custody lives inside the build system; it is "
     "not retrievable or verifiable from an external SaaS scan."),
    ("reproducible_build_verify",
     "Reproducible-build verification (playbook §5 #66)",
     "Reproducibility requires rebuilding from source in a controlled environment "
     "and bit-for-bit diffing — on-host work, not a remote probe."),
    ("commit_signing_audit",
     "Commit / tag signature audit (git verify-commit) (playbook §5 #69/#70)",
     "Verifying commit/tag signatures needs the full repository and the maintainers' "
     "trusted public keys; only meaningful with repo + keyring access."),

    # ── §6 Package registry org controls ──
    ("npm_2fa_enforcement",
     "npm 2FA-enforcement audit (playbook §6 #73)",
     "Whether an npm org enforces 2FA-for-publish is an org-admin setting readable "
     "only via an authenticated npm org token — not externally observable."),
    ("pypi_2fa_enforcement",
     "PyPI 2FA-enforcement audit (playbook §6 #74)",
     "PyPI 2FA enforcement is a maintainer/org account property; confirming it needs "
     "the account owner's authenticated session, not a remote scan."),
    ("install_script_behavior",
     "npm/PyPI install-script behavior analysis (playbook §6 #78/#79)",
     "Dynamically analyzing install/postinstall script behavior requires a sandboxed "
     "execution environment, not an external host probe (and execution is PT, not VA)."),

    # ── §7 Container image supply chain (cluster-side) ──
    ("image_pull_policy_audit",
     "Image pull-policy audit (Always vs IfNotPresent) (playbook §7 #89)",
     "Pull-policy is a Kubernetes workload spec field; reading it requires cluster "
     "kubeconfig access, which a SaaS external scan does not have."),
    ("registry_mirror_audit",
     "Registry mirror / pull-through configuration audit (playbook §7 #88)",
     "Mirror configuration lives in container-runtime / cluster config files on the "
     "nodes; it is not exposed to remote HTTP probing."),
    ("policy_controller_audit",
     "Sigstore policy-controller / admission audit (playbook §7 #91)",
     "Verifying signature-admission policy requires kubeconfig access to the cluster's "
     "admission webhooks and policy CRDs — not externally probeable."),
    ("image_promotion_integrity",
     "Image promotion pipeline integrity dev->prod (playbook §7 #92)",
     "Promotion-pipeline integrity spans CI config and registry ACLs the customer "
     "owns; assessing it needs pipeline + registry credentials, not a host scan."),

    # ── §8 OSS health (analyst judgement) ──
    ("maintainer_due_diligence",
     "Maintainer interview / due-diligence (playbook §8 #106)",
     "Maintainer trust scoring and due-diligence are analyst activities requiring "
     "human judgement and direct contact — not automatable from a remote scan."),
]


def _make_handler(slug: str, title: str, reason: str):
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        return _advisory_by_design_response(
            tool=slug, target=req.target, title=title, reason=reason,
            cwe="CWE-1357",
        )
    _h.__name__ = f"supply_chain_{slug}"
    return _h


for _slug, _title, _reason in _ADVISORY_TECHNIQUES:
    router.add_api_route(
        f"/api/supply_chain/{_slug}",
        _make_handler(_slug, _title, _reason),
        methods=["POST"],
    )


def register(app): app.include_router(router)
