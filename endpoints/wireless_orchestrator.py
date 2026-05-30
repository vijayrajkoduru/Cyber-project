"""Wireless module orchestrator — 18_wireless.md (57 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.wireless.wireless_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_wifi_recon",     0, 10),
    ("tier2_wep_wpa_wpa2",   10, 21),
    ("tier3_wpa3",           21, 26),
    ("tier4_enterprise_eap", 26, 33),
    ("tier5_evil_twin",      33, 40),
    ("tier6_bluetooth_ble",  40, 49),
    ("tier7_nfc_rfid",       49, 53),
    ("tier8_cellular_sdr",   53, 57),
]

WIRELESS_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/wireless/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class WirelessRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in WIRELESS_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/wireless/run_all")
async def wireless_run_all(req: WirelessRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="wireless", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/wireless/run_all/tiers")
async def wireless_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in WIRELESS_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in WIRELESS_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
