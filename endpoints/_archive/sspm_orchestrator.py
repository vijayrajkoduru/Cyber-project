"""SSPM orchestrator — 29_sspm.md (77 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.sspm.sspm_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_m365",     0, 15),
    ("tier2_gws",      15, 28),
    ("tier3_salesforce", 28, 37),
    ("tier4_slack_teams", 37, 46),
    ("tier5_atlassian", 46, 53),
    ("tier6_gh_org",    53, 62),
    ("tier7_oauth_apps", 62, 70),
    ("tier8_dlp",       70, 77),
]

SSPM_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/sspm/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class SspmRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in SSPM_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/sspm/run_all")
async def sspm_run_all(req: SspmRunAllRequest, request: Request,
                        _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="sspm", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/sspm/run_all/tiers")
async def sspm_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in SSPM_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in SSPM_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
