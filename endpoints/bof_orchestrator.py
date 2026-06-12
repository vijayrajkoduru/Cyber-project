"""bof module orchestrator - Buffer Overflow / Binary Exploitation static audit.

Per module_playbooks/07_bof.md - 8 sections, 80 techniques.

Static binary-analysis probes (REAL detection on an uploaded ELF / PE):
  - tier1_protections     (§6 / §8 Mitigation Audit):
        binary_protection_audit       NX/PIE/RELRO/Canary/Fortify
        dangerous_function_detect     strcpy/gets/sprintf/system call sites
        cfi_modern_mitigation_audit   Intel CET IBT/SHSTK + ARM PAC/BTI + PE CET
        aslr_textrel_audit            PIE/ASLR/DT_TEXTREL/DYNAMICBASE/relocs-stripped
  - tier2_exploit_surface (§2 / §4 / §6 / §7):
        rop_gadget_finder             ROPgadget pop/ret + stack-pivot count
        heap_metadata_audit           glibc allocator + safe-linking generation
        format_string_detect          capstone non-immediate printf-arg flow
        seh_overflow_audit            32-bit PE SafeSEH absence (SEH-overwrite)

Advisory-by-design (CANNOT be SaaS-probed - dynamic execution, live debugger,
weaponization, post-compromise foothold, specific silicon - emitted as honest
INFO, never a graded severity):
  - tier3_advisory        (§1 / §2-§5 / §7 / §6#60 / §8#75-80):
        fuzzing_crash_triage_advisory   §1 fuzzing + crash dedup/triage
        exploit_dev_primitive_advisory  §2-§5 offset/badchar/EIP/ROP-build/shellcode
        heap_exploit_advisory           §7 heap / UAF / tcache / House-of
        kernel_hw_mitigation_advisory   §6#60 KASLR + §8#75-80 PAC/MTE/hyperv/TEE

Customer input: ScanRequest.target = absolute path to an ELF or PE binary
that the customer has uploaded (dashboard upload widget stages files
under /tmp/vl_uploads/).

Concurrency 3 (binary disassembly + ROPgadget are CPU/IO heavy; running
more than three at once on a single uploaded binary saturates IO and the
GIL on capstone passes).
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
        ("binary_protection_audit",    "/api/bof/binary_protection_audit"),
        ("dangerous_function_detect",  "/api/bof/dangerous_function_detect"),
        ("cfi_modern_mitigation_audit", "/api/bof/cfi_modern_mitigation_audit"),
        ("aslr_textrel_audit",         "/api/bof/aslr_textrel_audit"),
    ],
    "tier2_exploit_surface": [
        ("rop_gadget_finder",          "/api/bof/rop_gadget_finder"),
        ("heap_metadata_audit",        "/api/bof/heap_metadata_audit"),
        ("format_string_detect",       "/api/bof/format_string_detect"),
        ("seh_overflow_audit",         "/api/bof/seh_overflow_audit"),
    ],
    "tier3_advisory": [
        ("fuzzing_crash_triage_advisory",  "/api/bof/fuzzing_crash_triage_advisory"),
        ("exploit_dev_primitive_advisory", "/api/bof/exploit_dev_primitive_advisory"),
        ("heap_exploit_advisory",          "/api/bof/heap_exploit_advisory"),
        ("kernel_hw_mitigation_advisory",  "/api/bof/kernel_hw_mitigation_advisory"),
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
