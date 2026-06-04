"""Password module orchestrator — 08_password.md (79 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.password.password_pack import TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_online_brute",   0, 13),
    ("tier2_offline_crack",  13, 28),
    ("tier3_stuff_spray",    28, 37),
    ("tier4_hash_id",        37, 45),
    ("tier5_wordlist_rule",  45, 55),
    ("tier6_cloud_crack",    55, 62),
    ("tier7_os_extraction",  62, 73),
    ("tier8_modern_bypass",  73, 79),
]

PASSWORD_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/password/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class PasswordRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in PASSWORD_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/password/run_all")
async def password_run_all(req: PasswordRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="password", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/password/run_all/tiers")
async def password_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in PASSWORD_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in PASSWORD_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
