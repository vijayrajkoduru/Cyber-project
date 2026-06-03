"""mobile_runtime module orchestrator — §2 RUNTIME / IN-MEMORY.

Static detection of anti-tamper mechanisms (root, anti-debug, anti-Frida,
emulator detection, Play Integrity attestation, iOS jailbreak detection).
§2 has ZERO fully-auto techniques - all bypasses require a connected device.
What we CAN do statically: tell the customer WHICH protections their app
has, so manual penetration testing knows exactly what to bypass.

Reuses the /api/mobile_static/upload endpoint (same uploaded APK, same
binary_cache.py SHA-256 cache).
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


MOBILE_RUNTIME_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_anti_tamper": [
        ("root_detection_audit",         "/api/mobile_runtime/root_detection_audit"),
        ("anti_debug_audit",             "/api/mobile_runtime/anti_debug_audit"),
        ("anti_frida_audit",             "/api/mobile_runtime/anti_frida_audit"),
        ("integrity_check_audit",        "/api/mobile_runtime/integrity_check_audit"),
        ("hook_detection_audit",         "/api/mobile_runtime/hook_detection_audit"),
        ("dyld_insert_library_audit",    "/api/mobile_runtime/dyld_insert_library_audit"),
        ("ndk_stack_canary_audit",       "/api/mobile_runtime/ndk_stack_canary_audit"),
        ("magisk_zygisk_audit",          "/api/mobile_runtime/magisk_zygisk_audit"),
    ],
    "tier2_attestation": [
        ("anti_emulator_audit",                "/api/mobile_runtime/anti_emulator_audit"),
        ("play_integrity_audit",               "/api/mobile_runtime/play_integrity_audit"),
        ("ios_jailbreak_detection_audit",      "/api/mobile_runtime/ios_jailbreak_detection_audit"),
        ("dynamic_code_loading_audit",         "/api/mobile_runtime/dynamic_code_loading_audit"),
        ("screen_overlay_protection_audit",    "/api/mobile_runtime/screen_overlay_protection_audit"),
        ("ptrace_block_audit",                 "/api/mobile_runtime/ptrace_block_audit"),
        ("method_swizzling_audit",             "/api/mobile_runtime/method_swizzling_audit"),
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in MOBILE_RUNTIME_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class MobileRuntimeRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 4
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in MOBILE_RUNTIME_TOOLS_BY_TIER:
                tools.extend(MOBILE_RUNTIME_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/mobile_runtime/run_all")
async def mobile_runtime_run_all(req: MobileRuntimeRunAllRequest, request: Request,
                                  _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="mobile_runtime",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/mobile_runtime/run_all_buffered")
async def mobile_runtime_run_all_buffered(req: MobileRuntimeRunAllRequest, request: Request,
                                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="mobile_runtime",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/mobile_runtime/run_all/tiers")
async def mobile_runtime_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in MOBILE_RUNTIME_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in MOBILE_RUNTIME_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
