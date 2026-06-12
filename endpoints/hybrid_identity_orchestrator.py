"""hybrid_identity module orchestrator - Entra ID + on-prem AD bridge attacks.

Per module_playbooks/28_hybrid_identity.md - 8 sections, 90 techniques.
Real unauthenticated/credentialed probes + an honest advisory-by-design
pack for everything that needs on-host/LAN/post-compromise/social
engineering/DoS (which an external SaaS scanner must NOT execute):
  - tier1_recon (§1 Entra ID Recon):
        entra_user_enum_unauth, seamless_sso_audit,
        openid_tenant_recon, tenant_domain_enum
  - tier2_sync  (§2 Hybrid AD Connect Attacks, Graph-authenticated):
        password_hash_sync_audit, pta_agent_audit
  - tier3_federation (§2 #20-26 + §3 #29/#36 + §8 modern CVE/TTPs):
        adfs_extract_audit, legacy_wstrust_surface_audit
  - tier4_advisory (everything not safely probeable externally):
        hybrid_identity_advisory_pack  (all INFO, [ADVISORY-BY-DESIGN])

Every graded (LOW/MEDIUM/HIGH/CRITICAL) severity is emitted ONLY when the
probe actually observed the condition on the target; advisory items are
always INFO with vulnerable:false (zero false positives).

Concurrency is intentionally LOW (3) because two of the scanners hit
login.microsoftonline.com (Microsoft will throttle aggressive fan-out)
and the Graph-authenticated scanners share a single tenant rate-limit
budget.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


HYBRID_IDENTITY_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_recon": [
        ("entra_user_enum_unauth",   "/api/hybrid_identity/entra_user_enum_unauth"),
        ("seamless_sso_audit",       "/api/hybrid_identity/seamless_sso_audit"),
        ("openid_tenant_recon",      "/api/hybrid_identity/openid_tenant_recon"),
        ("tenant_domain_enum",       "/api/hybrid_identity/tenant_domain_enum"),
    ],
    "tier2_sync": [
        ("password_hash_sync_audit", "/api/hybrid_identity/password_hash_sync_audit"),
        ("pta_agent_audit",          "/api/hybrid_identity/pta_agent_audit"),
    ],
    "tier3_federation": [
        ("adfs_extract_audit",       "/api/hybrid_identity/adfs_extract_audit"),
        ("legacy_wstrust_surface_audit",
         "/api/hybrid_identity/legacy_wstrust_surface_audit"),
    ],
    "tier4_advisory": [
        ("hybrid_identity_advisory_pack",
         "/api/hybrid_identity/hybrid_identity_advisory_pack"),
    ],
}


def _all_tools():
    out = []
    for tier in HYBRID_IDENTITY_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class HybridIdentityRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 3
    options: Optional[dict] = None


def _resolve(req: HybridIdentityRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in HYBRID_IDENTITY_TOOLS_BY_TIER:
                tools.extend(HYBRID_IDENTITY_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    # Forward customer options dict (tenant_id, client_id, client_secret,
    # username_list, adfs_server_url, etc.) as a nested 'options' key so each
    # scanner's ScanRequest subclass receives it.
    extra: dict = {}
    if req.options:
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/hybrid_identity/run_all")
async def hybrid_identity_run_all(req: HybridIdentityRunAllRequest, request: Request,
                                    _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 3 — login.microsoftonline.com throttles
    # aggressive fan-out + Graph shares a tenant-wide rate-limit budget.
    concurrency = max(1, min(req.concurrency or 3, 3))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="hybrid_identity",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )
    return StreamingResponse(
        gen,
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-store, no-transform",
            "Connection":        "keep-alive",
        },
    )


@router.post("/api/hybrid_identity/run_all_buffered")
async def hybrid_identity_run_all_buffered(req: HybridIdentityRunAllRequest, request: Request,
                                             _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 3, 3))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="hybrid_identity",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/hybrid_identity/run_all/tiers")
async def hybrid_identity_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in HYBRID_IDENTITY_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in HYBRID_IDENTITY_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
