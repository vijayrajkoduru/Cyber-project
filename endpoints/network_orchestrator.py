"""Network module orchestrator — 16_network.md (67 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.network.network_pack import TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_port_service_enum", 0, 14),
    ("tier2_lan_l2",            14, 23),
    ("tier3_mitm",              23, 30),
    ("tier4_dos_ddos",          30, 38),
    ("tier5_sniffing_capture",  38, 46),
    ("tier6_dns_attacks",       46, 55),
    ("tier7_ipv6",              55, 62),
    ("tier8_protocol_fuzzing",  62, 67),
]

NETWORK_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/network/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class NetworkRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in NETWORK_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/network/run_all")
async def network_run_all(req: NetworkRunAllRequest, request: Request,
                           _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="network", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/network/run_all/tiers")
async def network_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in NETWORK_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in NETWORK_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
