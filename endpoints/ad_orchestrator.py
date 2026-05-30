"""AD module orchestrator — 19_ad.md (99 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.ad.ad_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_discovery",         0,  16),
    ("tier2_credential_access", 16, 29),
    ("tier3_kerberoast_asrep",  29, 38),
    ("tier4_lateral_movement",  38, 48),
    ("tier5_privilege_esc",     48, 60),
    ("tier6_adcs_abuse",        60, 75),
    ("tier7_delegation",        75, 83),
    ("tier8_coercion",          83, 90),
    ("tier9_persistence",       90, 99),
    ("tier10_defense_evasion",  99, 104),
    ("tier11_modern_cve",       104, 113),
]

AD_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/ad/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class ADRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in AD_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/ad/run_all")
async def ad_run_all(req: ADRunAllRequest, request: Request,
                      _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="ad", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/ad/run_all/tiers")
async def ad_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in AD_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in AD_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
