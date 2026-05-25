"""mobile_network module orchestrator — §5 NETWORK / TRAFFIC.

8 static scanners covering OWASP MASVS-NETWORK + the non-overlapping
slices of §5 mobile_ruff. Reuses /api/mobile_static/upload (same
SHA-256-keyed binary_cache) so customers don't re-upload.

Tier 1 — Transport (3):
  - ssl_pinning_detection   (#56-#59 static side: lib + pins inventory)
  - proxy_bypass_audit       (proxy-detection / NO_PROXY patterns)
  - http_method_audit        (TRACE/CONNECT/PROPFIND + X-HTTP-Method-Override)

Tier 2 — Endpoint discovery (3):
  - endpoint_classifier      (#71 extended: classify URLs by purpose)
  - websocket_grpc_audit     (WS, gRPC, MQTT, Socket.IO, SSE)
  - network_lib_inventory    (OkHttp/Retrofit/Cronet versions for CVE lookup)

Tier 3 — Wireless surface (2):
  - ble_attack_surface       (#65/#66 detection: BLE perms + GATT APIs)
  - nfc_attack_surface       (#67/#68 detection: NFC perms + HCE service)
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import (
    run_module_parallel, run_module_streaming,
)

router = APIRouter()


MOBILE_NETWORK_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_transport": [
        ("ssl_pinning_detection",   "/api/mobile_network/ssl_pinning_detection"),
        ("proxy_bypass_audit",       "/api/mobile_network/proxy_bypass_audit"),
        ("http_method_audit",        "/api/mobile_network/http_method_audit"),
    ],
    "tier2_endpoint_discovery": [
        ("endpoint_classifier",     "/api/mobile_network/endpoint_classifier"),
        ("websocket_grpc_audit",    "/api/mobile_network/websocket_grpc_audit"),
        ("network_lib_inventory",   "/api/mobile_network/network_lib_inventory"),
    ],
    "tier3_wireless_surface": [
        ("ble_attack_surface",      "/api/mobile_network/ble_attack_surface"),
        ("nfc_attack_surface",      "/api/mobile_network/nfc_attack_surface"),
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in MOBILE_NETWORK_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class MobileNetworkRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 4
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in MOBILE_NETWORK_TOOLS_BY_TIER:
                tools.extend(MOBILE_NETWORK_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/mobile_network/run_all")
async def mobile_network_run_all(req: MobileNetworkRunAllRequest, request: Request,
                                   _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="mobile_network",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/mobile_network/run_all_buffered")
async def mobile_network_run_all_buffered(req: MobileNetworkRunAllRequest, request: Request,
                                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="mobile_network",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/mobile_network/run_all/tiers")
async def mobile_network_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in MOBILE_NETWORK_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in MOBILE_NETWORK_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
