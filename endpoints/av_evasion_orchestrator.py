"""av_evasion module orchestrator - EDR / AV detection-capability probes.

Per module_playbooks/20_av_evasion.md - 7 sections, 80 techniques.
Starter set (5 scanners):

  tier1_runtime_evasion (§2 AMSI / §3 ETW / §6 Encoded payload):
        amsi_bypass_detection_test, etw_bypass_detection_test,
        encoded_shellcode_detection_test
  tier2_advanced        (§4 Process Injection / §5 Indirect Syscalls):
        process_hollowing_detection_test, direct_syscall_detection_test

These probes flip the normal VulnusLab severity convention:
  HIGH      means the EDR DID NOT catch the technique - the customer
            has a defensive gap on that detection chain.
  POSITIVE  means the EDR caught the technique cleanly - good signal.
  INFO      means the probe could not run (no creds / connection error
            / pywinrm missing) - transparency.

Concurrency is hard-clamped to 2 because:
  1. Every probe holds a WinRM session against the same Windows host;
     > 2 simultaneous PowerShell sessions trip the MaxConcurrentUsers
     /MaxSessions WSMan limit on stock configs.
  2. Running multiple AV-bypass attempts at once would muddle the EDR
     telemetry the customer's IR team is supposed to read.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


AV_EVASION_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_runtime_evasion": [
        ("amsi_bypass_detection_test",       "/api/av_evasion/amsi_bypass_detection_test"),
        ("etw_bypass_detection_test",        "/api/av_evasion/etw_bypass_detection_test"),
        ("encoded_shellcode_detection_test", "/api/av_evasion/encoded_shellcode_detection_test"),
    ],
    "tier2_advanced": [
        ("process_hollowing_detection_test", "/api/av_evasion/process_hollowing_detection_test"),
        ("direct_syscall_detection_test",    "/api/av_evasion/direct_syscall_detection_test"),
    ],
}


def _all_tools():
    out = []
    for tier in AV_EVASION_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class AvEvasionRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 2
    options: Optional[dict] = None


def _resolve(req: AvEvasionRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in AV_EVASION_TOOLS_BY_TIER:
                tools.extend(AV_EVASION_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    # Nest customer options so each scanner reads via req.options
    extra: dict = {}
    if req.options:
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/av_evasion/run_all")
async def av_evasion_run_all(req: AvEvasionRunAllRequest, request: Request,
                              _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 2 - WinRM MaxConcurrentUsers + EDR-telemetry
    # signal clarity.
    concurrency = max(1, min(req.concurrency or 2, 2))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="av_evasion",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )
    return StreamingResponse(
        gen,
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-store, no-transform",
            "Connection":        "keep-alive",
        },
    )


@router.post("/api/av_evasion/run_all_buffered")
async def av_evasion_run_all_buffered(req: AvEvasionRunAllRequest, request: Request,
                                       _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 2))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="av_evasion",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/av_evasion/run_all/tiers")
async def av_evasion_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in AV_EVASION_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in AV_EVASION_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
