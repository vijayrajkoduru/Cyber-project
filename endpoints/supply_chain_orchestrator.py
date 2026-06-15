"""supply_chain module orchestrator - OSS supply-chain audit.

Per module_playbooks/25_supply_chain.md - 8 sections, 106 techniques.
Starter set (5 scanners) covers the Anchore/Aquasec/Gitleaks stack:
  - tier1_vuln_scan: trivy_image_scan, grype_sbom_scan, osv_repo_audit
  - tier2_secrets:   gitleaks_secrets_scan
  - tier3_sbom:      syft_sbom_generate

More scanners will be added per playbook section in subsequent commits
(SLSA verifier, cosign verify, scorecard, actionlint, npm-audit, etc.).
"""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


SUPPLY_CHAIN_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_vuln_scan": [
        ("trivy_image_scan",          "/api/supply_chain/trivy_image_scan"),
        ("grype_sbom_scan",           "/api/supply_chain/grype_sbom_scan"),
        ("osv_repo_audit",            "/api/supply_chain/osv_repo_audit"),
        ("npm_audit_scanner",         "/api/supply_chain/npm_audit_scanner"),
        ("cargo_audit_scanner",       "/api/supply_chain/cargo_audit_scanner"),
        ("govulncheck_scanner",       "/api/supply_chain/govulncheck_scanner"),
        ("pip_audit_scanner",         "/api/supply_chain/pip_audit_scanner"),
        ("bundler_audit_scanner",     "/api/supply_chain/bundler_audit_scanner"),
        ("transitive_dependency_depth", "/api/supply_chain/transitive_dependency_depth"),
    ],
    "tier2_secrets": [
        ("gitleaks_secrets_scan",    "/api/supply_chain/gitleaks_secrets_scan"),
        ("trufflehog_secrets_scan",  "/api/supply_chain/trufflehog_secrets_scan"),
    ],
    # ── Install/build-time script behavior audit (ADVISORY INFO/LOW only) ──
    "tier2_install": [
        ("install_script_audit",     "/api/supply_chain/install_script_audit"),
    ],
    "tier3_sbom": [
        ("syft_sbom_generate",        "/api/supply_chain/syft_sbom_generate"),
        ("license_compliance_audit",  "/api/supply_chain/license_compliance_audit"),
    ],
    # ── Real remote probes (read-only, zero-FP, VA-only) ──
    "tier4_registry": [
        ("registry_exposure_probe", "/api/supply_chain/registry_exposure_probe"),
    ],
    "tier5_oss_health": [
        ("github_repo_health",      "/api/supply_chain/github_repo_health"),
        ("commit_signing_audit",    "/api/supply_chain/commit_signing_audit"),
    ],
    "tier6_cicd": [
        ("cicd_exposure_probe",     "/api/supply_chain/cicd_exposure_probe"),
    ],
    "tier7_dep_confusion": [
        ("npm_dependency_confusion", "/api/supply_chain/npm_dependency_confusion"),
        ("npm_typosquat_scan",       "/api/supply_chain/npm_typosquat_scan"),
        ("pypi_typosquat_scan",      "/api/supply_chain/pypi_typosquat_scan"),
    ],
    "tier9_iac": [
        ("checkov_scanner",          "/api/supply_chain/checkov_scanner"),
    ],
    # ── Honest advisory-by-design techniques (INFO only; cannot be SaaS-probed) ──
    "tier8_advisory": [
        ("sbom_signing_attest",        "/api/supply_chain/sbom_signing_attest"),
        ("sbom_rekor_transparency",    "/api/supply_chain/sbom_rekor_transparency"),
        ("sbom_vex_audit",             "/api/supply_chain/sbom_vex_audit"),
        ("gha_oidc_cloud_trust",       "/api/supply_chain/gha_oidc_cloud_trust"),
        ("branch_protection_audit",    "/api/supply_chain/branch_protection_audit"),
        ("pwn_request_audit",          "/api/supply_chain/pwn_request_audit"),
        ("self_hosted_runner_audit",   "/api/supply_chain/self_hosted_runner_audit"),
        ("slsa_provenance_verify",     "/api/supply_chain/slsa_provenance_verify"),
        ("cosign_signature_verify",    "/api/supply_chain/cosign_signature_verify"),
        ("intoto_attestation_validate", "/api/supply_chain/intoto_attestation_validate"),
        ("reproducible_build_verify",  "/api/supply_chain/reproducible_build_verify"),
        ("commit_signing_audit",       "/api/supply_chain/commit_signing_audit"),
        ("npm_2fa_enforcement",        "/api/supply_chain/npm_2fa_enforcement"),
        ("pypi_2fa_enforcement",       "/api/supply_chain/pypi_2fa_enforcement"),
        ("install_script_behavior",    "/api/supply_chain/install_script_behavior"),
        ("image_pull_policy_audit",    "/api/supply_chain/image_pull_policy_audit"),
        ("registry_mirror_audit",      "/api/supply_chain/registry_mirror_audit"),
        ("policy_controller_audit",    "/api/supply_chain/policy_controller_audit"),
        ("image_promotion_integrity",  "/api/supply_chain/image_promotion_integrity"),
        ("maintainer_due_diligence",   "/api/supply_chain/maintainer_due_diligence"),
    ],
}


def _all_tools():
    out = []
    for tier in SUPPLY_CHAIN_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class SupplyChainRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 3
    options: Optional[dict] = None
    # Customer-provided supply-chain inputs forwarded to every scanner.
    image_ref: Optional[str] = None
    repo_url: Optional[str] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in SUPPLY_CHAIN_TOOLS_BY_TIER:
                tools.extend(SUPPLY_CHAIN_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    extra = dict(req.options or {})
    if req.image_ref: extra["image_ref"] = req.image_ref
    if req.repo_url:  extra["repo_url"] = req.repo_url
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, extra, jwt


@router.post("/api/supply_chain/run_all")
async def supply_chain_run_all(req: SupplyChainRunAllRequest, request: Request,
                                  _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 3, 8))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="supply_chain",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )
    return StreamingResponse(
        gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"},
    )


@router.post("/api/supply_chain/run_all_buffered")
async def supply_chain_run_all_buffered(req: SupplyChainRunAllRequest, request: Request,
                                           _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 3, 8))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="supply_chain",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )


@router.get("/api/supply_chain/run_all/tiers")
async def supply_chain_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in SUPPLY_CHAIN_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in SUPPLY_CHAIN_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
