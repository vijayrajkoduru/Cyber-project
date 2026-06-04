"""Hybrid Identity orchestrator — 28_hybrid_identity.md (74 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.hybrid_identity.hybrid_identity_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_entra_recon",     0, 13),
    ("tier2_aadconnect",      13, 23),
    ("tier3_ca_bypass",       23, 30),
    ("tier4_token_theft",     30, 38),
    ("tier5_sp_app_reg",      38, 49),
    ("tier6_cross_tenant",    49, 56),
    ("tier7_m365_privesc",    56, 66),
    ("tier8_modern_cve",      66, 74),
]

HYBRID_IDENTITY_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/hybrid_identity/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class HybridIdentityRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in HYBRID_IDENTITY_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/hybrid_identity/run_all")
async def hybrid_identity_run_all(req: HybridIdentityRunAllRequest, request: Request,
                                    _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="hybrid_identity", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/hybrid_identity/run_all/tiers")
async def hybrid_identity_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in HYBRID_IDENTITY_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in HYBRID_IDENTITY_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
