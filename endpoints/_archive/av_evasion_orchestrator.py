"""AV Evasion module orchestrator — 20_av_evasion.md (72 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.av_evasion.av_evasion_pack import TECHNIQUES

router = APIRouter()

# Split TECHNIQUES into the 7 sections by index range matching the playbook.
_SECTION_RANGES = [
    ("tier1_detection_profile", 0, 10),
    ("tier2_amsi_bypass",       10, 20),
    ("tier3_etw_bypass",        20, 28),
    ("tier4_injection_hollow",  28, 40),
    ("tier5_indirect_syscalls", 40, 50),
    ("tier6_obfuscation_pack",  50, 60),
    ("tier7_modern_edr_bypass", 60, 72),
]

AV_EVASION_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    tier_id: [(t[0], f"/api/av_evasion/{t[0]}") for t in TECHNIQUES[a:b]]
    for tier_id, a, b in _SECTION_RANGES
}


class AvEvasionRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in AV_EVASION_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/av_evasion/run_all")
async def av_evasion_run_all(req: AvEvasionRunAllRequest, request: Request,
                              _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    generator = run_module_streaming(target=req.target, tools=_all_tools(),
        module_name="av_evasion", concurrency=max(1, min(req.concurrency or 16, 32)),
        auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
        extra_body=None, jwt_token=jwt_token)
    return StreamingResponse(generator, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/av_evasion/run_all/tiers")
async def av_evasion_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in AV_EVASION_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in AV_EVASION_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
