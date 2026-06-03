"""ndk_stack_canary_audit - Native lib hardening: stack canaries (SSP),
RELRO, NX, PIE. ELF section / dynamic-tag inspection of bundled .so files.
MASVS-CODE-3. Catches NDK builds without -fstack-protector-strong or
position-independent execution (=ASLR off)."""
from __future__ import annotations
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.ndk_stack_canary_audit_findings import NDK_STACK_CANARY_AUDIT_FINDING_RULES

router = APIRouter()


def _has_section(blob: bytes, marker: bytes) -> bool:
    return marker in blob


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ndk_stack_canary_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["ndk_stack_canary_audit_error"] = str(e); return
    libs_scanned = 0
    libs = []  # list of dicts: {name, canary, relro_full, nx, pie}
    for p in unpacked.rglob("*.so"):
        if libs_scanned >= 40: break
        try: blob = p.read_bytes()[:5_000_000]
        except OSError: continue
        libs_scanned += 1
        # ELF magic
        if not blob.startswith(b"\x7fELF"): continue
        canary = _has_section(blob, b"__stack_chk_fail") or _has_section(blob, b"__stack_chk_guard")
        relro_full = _has_section(blob, b"GNU_RELRO") and _has_section(blob, b"BIND_NOW")
        relro_partial = _has_section(blob, b"GNU_RELRO")
        nx = _has_section(blob, b"GNU_STACK")
        # PIE: e_type field at offset 16 = 3 (ET_DYN) for PIE
        try:
            e_type = blob[16]
            pie = (e_type == 3)
        except IndexError:
            pie = False
        libs.append({
            "name": p.name,
            "canary": canary,
            "relro_full": relro_full,
            "relro_partial": relro_partial,
            "nx": nx,
            "pie": pie,
        })
    # Build weakness flags
    no_canary = [l["name"] for l in libs if not l["canary"]]
    no_relro = [l["name"] for l in libs if not l["relro_full"]]
    no_pie = [l["name"] for l in libs if not l["pie"]]
    findings_total = 0
    if no_canary: findings_total += 1
    if no_relro: findings_total += 1
    if no_pie: findings_total += 1
    ctx.state["libs_scanned"] = libs_scanned
    ctx.state["libs_summary"] = libs[:25]
    ctx.state["no_canary"] = no_canary[:20]
    ctx.state["no_relro"] = no_relro[:20]
    ctx.state["no_pie"] = no_pie[:20]
    ctx.state["ndk_stack_canary_audit_total"] = findings_total
    ctx.source(f"{libs_scanned} ELF libs")


INTEL_FIELDS = [("Libs scanned", "libs_scanned"),
                ("Per-lib summary", "libs_summary"),
                ("No stack canary", "no_canary"),
                ("No full RELRO", "no_relro"),
                ("No PIE", "no_pie")]


@router.post("/api/mobile_runtime/ndk_stack_canary_audit")
async def mobile_runtime_ndk_stack_canary_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="ndk_stack_canary_audit",
        gather_func=gather, finding_rules=NDK_STACK_CANARY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
