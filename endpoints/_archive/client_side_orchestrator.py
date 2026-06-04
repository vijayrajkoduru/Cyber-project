"""Client-Side module orchestrator — 09_client_side.md (56 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.client_side.client_side_pack import TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_beef_hooks",       0, 8),
    ("tier2_office_macros",    8, 18),
    ("tier3_hta",              18, 23),
    ("tier4_lnk_shortcut",     23, 30),
    ("tier5_browser_exploit",  30, 38),
    ("tier6_payload_delivery", 38, 49),
    ("tier7_modern_browser",   49, 56),
]

CLIENT_SIDE_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/client_side/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class ClientSideRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in CLIENT_SIDE_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/client_side/run_all")
async def client_side_run_all(req: ClientSideRunAllRequest, request: Request,
                                _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="client_side", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/client_side/run_all/tiers")
async def client_side_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in CLIENT_SIDE_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in CLIENT_SIDE_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
