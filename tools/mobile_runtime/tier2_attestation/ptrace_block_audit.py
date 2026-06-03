"""ptrace_block_audit - Linux ptrace anti-debug via prctl(PR_SET_DUMPABLE)
and prctl(PR_SET_PTRACER, 0). Standard root/Frida-resistance technique on
Android NDK. MSTG-RESILIENCE-2."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.ptrace_block_audit_findings import PTRACE_BLOCK_AUDIT_FINDING_RULES

router = APIRouter()
PRCTL_RE = re.compile(r"prctl|PR_SET_DUMPABLE|PR_SET_PTRACER|PT_TRACE_ME|ptrace\s*\(\s*PTRACE_TRACEME")
NATIVE_LIB_RE = re.compile(r"\.so$|System\.loadLibrary\(", re.IGNORECASE)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ptrace_block_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["ptrace_block_audit_error"] = str(e); return
    prctl_files = []
    native_libs_present = False
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file(): continue
        if p.suffix == ".so":
            native_libs_present = True
            try: blob = p.read_bytes()
            except OSError: continue
            files_scanned += 1
            if b"prctl" in blob or b"PR_SET_DUMPABLE" in blob or b"PTRACE_TRACEME" in blob:
                if len(prctl_files) < 20:
                    prctl_files.append(p.name)
            continue
        if p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if NATIVE_LIB_RE.search(txt):
            native_libs_present = True
        if PRCTL_RE.search(txt) and len(prctl_files) < 20:
            prctl_files.append(p.name)
    findings_total = 0
    if native_libs_present and not prctl_files:
        findings_total += 1
    ctx.state["prctl_users"] = prctl_files
    ctx.state["native_libs_present"] = native_libs_present
    ctx.state["files_scanned"] = files_scanned
    ctx.state["ptrace_block_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("prctl/PTRACE users", "prctl_users"),
                ("Native libs present", "native_libs_present")]


@router.post("/api/mobile_runtime/ptrace_block_audit")
async def mobile_runtime_ptrace_block_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="ptrace_block_audit",
        gather_func=gather, finding_rules=PTRACE_BLOCK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
