"""hook_detection_audit - Xposed / Substrate / Cydia / runtime hook detection
beyond Frida (covered separately). MSTG-RESILIENCE-5."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.hook_detection_audit_findings import HOOK_DETECTION_AUDIT_FINDING_RULES

router = APIRouter()
XPOSED_RE = re.compile(r"de\.robv\.android\.xposed|XposedBridge|XposedHelpers|XC_MethodHook")
SUBSTRATE_RE = re.compile(r"com\.saurik\.substrate|MS\.hookFunction|cydia\.MobileSubstrate")
CYDIA_PATH_RE = re.compile(r"/Library/MobileSubstrate|/usr/lib/substrate|/Applications/Cydia\.app")
STACK_INSPECTION_RE = re.compile(r"getStackTrace|fillInStackTrace|StackTraceElement")
LIB_INSPECTION_RE = re.compile(r"/proc/self/maps|getRuntime\(\)\.exec.*proc")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["hook_detection_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["hook_detection_audit_error"] = str(e); return
    xposed_check, substrate_check = [], []
    stack_check, lib_check = 0, 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if XPOSED_RE.search(txt) and len(xposed_check) < 20:
            xposed_check.append(p.name)
        if (SUBSTRATE_RE.search(txt) or CYDIA_PATH_RE.search(txt)) and len(substrate_check) < 20:
            substrate_check.append(p.name)
        if STACK_INSPECTION_RE.search(txt): stack_check += 1
        if LIB_INSPECTION_RE.search(txt): lib_check += 1
    findings_total = 0
    if not xposed_check and not substrate_check and stack_check == 0:
        findings_total += 1
    ctx.state["xposed_checks"] = xposed_check
    ctx.state["substrate_cydia_checks"] = substrate_check
    ctx.state["stack_inspection"] = stack_check
    ctx.state["proc_self_maps_inspection"] = lib_check
    ctx.state["files_scanned"] = files_scanned
    ctx.state["hook_detection_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Xposed-aware classes", "xposed_checks"),
                ("Substrate/Cydia checks", "substrate_cydia_checks"),
                ("Stack-trace inspections", "stack_inspection"),
                ("/proc/self/maps reads", "proc_self_maps_inspection")]


@router.post("/api/mobile_runtime/hook_detection_audit")
async def mobile_runtime_hook_detection_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="hook_detection_audit",
        gather_func=gather, finding_rules=HOOK_DETECTION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
