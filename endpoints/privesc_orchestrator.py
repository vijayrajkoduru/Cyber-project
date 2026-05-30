"""PrivEsc module orchestrator — 12_privesc.md (78 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.privesc.privesc_pack import TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_linux_enum",     0, 17),
    ("tier2_windows_enum",   17, 34),
    ("tier3_macos_enum",     34, 42),
    ("tier4_sudo_suid_caps", 42, 53),
    ("tier5_service_cron",   53, 62),
    ("tier6_kernel_cve",     62, 71),
    ("tier7_container_cloud", 71, 78),
]

PRIVESC_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/privesc/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class PrivescRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in PRIVESC_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/privesc/run_all")
async def privesc_run_all(req: PrivescRunAllRequest, request: Request,
                           _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="privesc", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/privesc/run_all/tiers")
async def privesc_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in PRIVESC_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in PRIVESC_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
