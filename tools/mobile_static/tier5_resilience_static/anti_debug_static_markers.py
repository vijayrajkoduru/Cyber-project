"""anti_debug_static_markers — static markers for debugger / Frida detection.

Searches the unpacked binary for known anti-debug API calls and Frida
runtime markers. Apps doing high-value transactions (banking, payments,
crypto wallets) should detect attached debuggers or Frida instrumentation.

MASVS-RESILIENCE-2 / MSTG-RESILIENCE-2.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.anti_debug_static_markers_findings import \
    ANTI_DEBUG_STATIC_MARKERS_FINDING_RULES

router = APIRouter()

DEBUG_MARKERS = [
    # Android debug APIs
    "Debug.isDebuggerConnected", "android/os/Debug",
    "Debug;->isDebuggerConnected", "ApplicationInfo.FLAG_DEBUGGABLE",
    # Frida-specific markers
    "frida-server", "frida-agent", "frida-gum",
    "gum-js-loop", "gmain", "linjector",
    "re.frida.server", "fridaserver",
    # JDB / ptrace strings (ELF debug)
    "ptrace(", "PTRACE_TRACEME", "TracerPid:",
    # iOS sysctl markers
    "P_TRACED", "sysctl(", "KERN_PROC",
    # Generic
    "jdwp", "android_server",
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["anti_debug_static_markers_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["anti_debug_static_markers_error"] = str(e); return

    matched = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".so", ".smali", ".xml"):
            if "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:5_000_000]
        except Exception: continue
        files_scanned += 1
        for marker in DEBUG_MARKERS:
            if marker.encode() in data:
                matched.append({"marker": marker, "file": f.relative_to(unpacked).as_posix()})
                if len(matched) > 30: break
        if len(matched) > 30: break

    ctx.state["anti_debug_markers_found"] = matched
    ctx.state["anti_debug_static_markers_total"] = len(matched)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} files")


INTEL_FIELDS = [
    ("Anti-debug markers found", "anti_debug_static_markers_total"),
    ("Files scanned",            "files_scanned"),
]


@router.post("/api/mobile_static/anti_debug_static_markers")
async def mobile_static_anti_debug_static_markers(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="anti_debug_static_markers",
        gather_func=gather,
        finding_rules=ANTI_DEBUG_STATIC_MARKERS_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
