"""bof module orchestrator - Buffer Overflow / Binary Exploitation static audit.

Per module_playbooks/07_bof.md - 8 sections, 80 techniques.
Starter set (5 scanners) covers the highest-impact playbook items:
  - tier1_protections     (§6 Mitigation Audit):
        binary_protection_audit, dangerous_function_detect
  - tier2_exploit_surface (§4 ROP / §7 Heap / §6 Format-String):
        rop_gadget_finder, heap_metadata_audit, format_string_detect

Customer input: ScanRequest.target = absolute path to an ELF or PE binary
that the customer has uploaded (dashboard upload widget stages files
under /tmp/vl_uploads/).

Concurrency 3 (binary disassembly + ROPgadget are CPU/IO heavy; running
more than three at once on a single uploaded binary saturates IO and the
GIL on capstone passes).  More scanners (boofuzz, ret2libc auto-rop,
CET/PAC audit, heap house-of-* primitives, exploitable / casr crash
triage) will be added per playbook section in subsequent commits.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


BOF_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_protections": [
        ("binary_protection_audit",   "/api/bof/binary_protection_audit"),
        ("dangerous_function_detect", "/api/bof/dangerous_function_detect"),
    ],
    "tier2_exploit_surface": [
        ("rop_gadget_finder",         "/api/bof/rop_gadget_finder"),
        ("heap_metadata_audit",       "/api/bof/heap_metadata_audit"),
        ("format_string_detect",      "/api/bof/format_string_detect"),
    ],
}


def _all_tools():
    out = []
    for tier in BOF_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class BofRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 3
    options: Optional[dict] = None


def _resolve(req: BofRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in BOF_TOOLS_BY_TIER:
                tools.extend(BOF_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    # Nest customer options so each scanner can pick them up via req.options
    # (the orchestrator flattens extra_body into the per-tool body).
    extra: dict = {}
    if req.options:
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/bof/run_all")
async def bof_run_all(req: BofRunAllRequest, request: Request,
                      _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 3, 3))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="bof",
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


@router.post("/api/bof/run_all_buffered")
async def bof_run_all_buffered(req: BofRunAllRequest, request: Request,
                                _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 3, 3))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="bof",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/bof/run_all/tiers")
async def bof_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in BOF_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in BOF_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
