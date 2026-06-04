"""BOF module orchestrator — 07_bof.md (53 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.bof.bof_pack import TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_fuzzing",       0, 10),
    ("tier2_eip_rip",       10, 18),
    ("tier3_badchars",      18, 23),
    ("tier4_rop_gadgets",   23, 31),
    ("tier5_shellcode",     31, 40),
    ("tier6_mit_bypass",    40, 46),
    ("tier7_heap_uaf",      46, 50),
    ("tier8_modern_bypass", 50, 53),
]

BOF_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/bof/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class BofRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in BOF_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/bof/run_all")
async def bof_run_all(req: BofRunAllRequest, request: Request,
                       _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="bof", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/bof/run_all/tiers")
async def bof_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in BOF_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in BOF_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
