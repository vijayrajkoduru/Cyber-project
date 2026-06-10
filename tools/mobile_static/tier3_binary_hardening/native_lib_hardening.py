"""native_lib_hardening — checksec audit on every .so file in the APK/IPA."""
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.native_lib_hardening_findings import NATIVE_LIB_HARDENING_FINDING_RULES

router = APIRouter()


def _parse_checksec(out: str) -> dict:
    """Best-effort parse of checksec output. Returns dict of flag -> bool."""
    flags = {"NX": False, "PIE": False, "RELRO": False, "Canary": False, "Fortify": False}
    low = out.lower()
    flags["NX"]      = "nx enabled" in low or "nx_enabled" in low
    flags["PIE"]     = "pie enabled" in low or "pie_enabled" in low
    flags["RELRO"]   = "full relro" in low or "partial relro" in low
    flags["Canary"]  = "canary found" in low or "stack canary" in low
    flags["Fortify"] = "yes" in low and "fortify" in low
    return flags


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["native_lib_hardening_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["native_lib_hardening_error"] = str(e)
        return

    libs = list(unpacked.rglob("*.so"))[:30]  # cap at 30 libs
    if not libs:
        ctx.state["native_lib_hardening_total"] = 0
        ctx.source("no-native-libs")
        return

    has_checksec = bool(subprocess.run(["which", "checksec"],
                                        capture_output=True).stdout.strip())
    weak_libs = []
    for lib in libs:
        flags = {"NX": False, "PIE": False, "RELRO": False, "Canary": False, "Fortify": False}
        if has_checksec:
            try:
                r = subprocess.run(["checksec", "--file=" + str(lib)],
                                    capture_output=True, text=True, timeout=15)
                flags = _parse_checksec(r.stdout + r.stderr)
            except (subprocess.TimeoutExpired, OSError):
                continue
        else:
            # Fallback — parse ELF program headers manually via readelf
            try:
                r = subprocess.run(["readelf", "-l", str(lib)],
                                    capture_output=True, text=True, timeout=15)
                flags["NX"]  = "GNU_STACK" in r.stdout and "RWE" not in r.stdout
                flags["PIE"] = "Type: DYN" in r.stdout
                flags["RELRO"] = "GNU_RELRO" in r.stdout
            except (subprocess.TimeoutExpired, OSError):
                continue

        weak = [k for k, v in flags.items() if not v]
        if weak:
            weak_libs.append({"lib": lib.name, "missing": weak})

    ctx.state["weak_libs"] = weak_libs
    ctx.state["native_lib_hardening_total"] = len(weak_libs)
    ctx.state["libs_audited"] = len(libs)
    ctx.source("checksec" if has_checksec else "readelf-fallback")


INTEL_FIELDS = [
    ("Weakly-hardened libs", "native_lib_hardening_total"),
    ("Libs audited", "libs_audited"),
]


@router.post("/api/mobile_static/native_lib_hardening")
async def mobile_static_native_lib_hardening(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="native_lib_hardening",
        gather_func=gather,
        finding_rules=NATIVE_LIB_HARDENING_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
