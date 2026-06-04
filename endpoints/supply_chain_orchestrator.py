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
        ("trivy_image_scan",       "/api/supply_chain/trivy_image_scan"),
        ("grype_sbom_scan",        "/api/supply_chain/grype_sbom_scan"),
        ("osv_repo_audit",         "/api/supply_chain/osv_repo_audit"),
        ("npm_audit_scanner",      "/api/supply_chain/npm_audit_scanner"),
    ],
    "tier2_secrets": [
        ("gitleaks_secrets_scan",  "/api/supply_chain/gitleaks_secrets_scan"),
    ],
    "tier3_sbom": [
        ("syft_sbom_generate",     "/api/supply_chain/syft_sbom_generate"),
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
