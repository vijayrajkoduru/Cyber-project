"""anti_debug_audit — detect anti-debugging mechanisms in the binary.
Both Java-side (Debug.isDebuggerConnected) and native-side (ptrace).
A complete app should have BOTH; bypassable individually with Frida."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.anti_debug_audit_findings import ANTI_DEBUG_AUDIT_FINDING_RULES

router = APIRouter()

ANTI_DEBUG_MARKERS = {
    "Debug.isDebuggerConnected":     ["android/os/Debug;->isDebuggerConnected", "Debug.isDebuggerConnected"],
    "Debug.waitingForDebugger":      ["android/os/Debug;->waitingForDebugger", "Debug.waitingForDebugger"],
    "BuildConfig.DEBUG check":       ["BuildConfig", "/BuildConfig;->DEBUG"],
    "ApplicationInfo FLAG_DEBUGGABLE": ["FLAG_DEBUGGABLE", "applicationInfo.flags"],
    "ptrace native call":            ["ptrace", "PTRACE_TRACEME"],
    "TracerPid /proc/self/status":   ['"TracerPid"', "/proc/self/status"],
}
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["anti_debug_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["anti_debug_audit_error"] = str(e)
        return

    java_protections = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for mech_name, markers in ANTI_DEBUG_MARKERS.items():
            for m in markers:
                if m in txt:
                    java_protections.setdefault(mech_name, [])
                    if len(java_protections[mech_name]) < 5 and p.name not in java_protections[mech_name]:
                        java_protections[mech_name].append(p.name)
                    break

    # Native: scan .so files for ptrace string (cheap heuristic — full elf scan would need objdump)
    native_protections = []
    for so in (unpacked / "lib").rglob("*.so"):
        try:
            data = so.read_bytes()
        except OSError:
            continue
        if b"ptrace" in data or b"PTRACE_TRACEME" in data:
            native_protections.append(so.name)
        if len(native_protections) >= 20:
            break

    ctx.state["java_anti_debug"] = java_protections
    ctx.state["native_anti_debug"] = native_protections
    ctx.state["files_scanned"] = files_scanned
    ctx.state["anti_debug_audit_total"] = len(java_protections) + (1 if native_protections else 0)
    ctx.source(f"{files_scanned} smali + {len(list((unpacked / 'lib').rglob('*.so')))} .so files")


INTEL_FIELDS = [
    ("Java anti-debug markers", "java_anti_debug"),
    ("Native libs with ptrace", "native_anti_debug"),
]


@router.post("/api/mobile_runtime/anti_debug_audit")
async def mobile_runtime_anti_debug_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="anti_debug_audit",
        gather_func=gather,
        finding_rules=ANTI_DEBUG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
