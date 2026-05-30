"""Red Team module orchestrator — 27_red_team.md (88 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.red_team.red_team_pack import TECHNIQUES

router = APIRouter()

_SECTION_RANGES = [
    ("tier1_emulation_plans",      0, 10),
    ("tier2_atomic_red_team",      10, 24),
    ("tier3_caldera",              24, 34),
    ("tier4_c2_frameworks",        34, 48),
    ("tier5_initial_access_sim",   48, 58),
    ("tier6_detection_eng_val",    58, 68),
    ("tier7_purple_teaming",       68, 76),
    ("tier8_threat_actor_emul",    76, 88),
]

RED_TEAM_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    tier_id: [(t[0], f"/api/red_team/{t[0]}") for t in TECHNIQUES[a:b]]
    for tier_id, a, b in _SECTION_RANGES
}


class RedTeamRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in RED_TEAM_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/red_team/run_all")
async def red_team_run_all(req: RedTeamRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    generator = run_module_streaming(target=req.target, tools=_all_tools(),
        module_name="red_team", concurrency=max(1, min(req.concurrency or 16, 32)),
        auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
        extra_body=None, jwt_token=jwt_token)
    return StreamingResponse(generator, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/red_team/run_all/tiers")
async def red_team_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in RED_TEAM_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in RED_TEAM_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
