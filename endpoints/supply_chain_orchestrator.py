"""Supply Chain module orchestrator — 25_supply_chain.md (95 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.supply_chain.supply_chain_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_sbom",          0, 13),
    ("tier2_sca",           13, 28),
    ("tier3_dep_confusion", 28, 37),
    ("tier4_cicd",          37, 52),
    ("tier5_slsa_provenance", 52, 65),
    ("tier6_registry",      65, 76),
    ("tier7_image_supply",  76, 87),
    ("tier8_oss_health",    87, 95),
]

SUPPLY_CHAIN_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/supply_chain/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class SupplyChainRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in SUPPLY_CHAIN_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/supply_chain/run_all")
async def supply_chain_run_all(req: SupplyChainRunAllRequest, request: Request,
                                 _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="supply_chain", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/supply_chain/run_all/tiers")
async def supply_chain_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in SUPPLY_CHAIN_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in SUPPLY_CHAIN_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
