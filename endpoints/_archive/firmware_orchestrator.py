"""Firmware orchestrator — 31_firmware.md (47 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.firmware.firmware_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_acquisition",   0, 6),
    ("tier2_static_analysis", 6, 17),
    ("tier3_fs_extraction", 17, 25),
    ("tier4_reverse_eng",   25, 31),
    ("tier5_bootloader",    31, 36),
    ("tier6_uart_jtag",     36, 39),
    ("tier7_side_channel",  39, 41),
    ("tier8_modern",        41, 47),
]

FIRMWARE_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/firmware/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class FirmwareRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in FIRMWARE_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/firmware/run_all")
async def firmware_run_all(req: FirmwareRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="firmware", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/firmware/run_all/tiers")
async def firmware_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in FIRMWARE_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in FIRMWARE_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
