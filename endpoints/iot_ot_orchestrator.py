"""IoT/OT orchestrator — 30_iot_ot.md (58 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.iot_ot.iot_ot_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_ics_discovery",  0, 11),
    ("tier2_modbus_dnp3",    11, 19),
    ("tier3_siemens_vendor", 19, 26),
    ("tier4_bacnet_knx",     26, 32),
    ("tier5_iot_recon",      32, 45),
    ("tier6_zigbee_zwave",   45, 50),
    ("tier7_matter",         50, 54),
    ("tier8_ot_methodology", 54, 58),
]

IOT_OT_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/iot_ot/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class IoTOtRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in IOT_OT_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/iot_ot/run_all")
async def iot_ot_run_all(req: IoTOtRunAllRequest, request: Request,
                          _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="iot_ot", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/iot_ot/run_all/tiers")
async def iot_ot_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in IOT_OT_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in IOT_OT_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
