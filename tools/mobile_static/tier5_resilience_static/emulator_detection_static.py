"""emulator_detection_static — markers for emulator-detect code.

Apps doing high-value transactions should detect when running on an
emulator (Android Studio AVD, Genymotion, BlueStacks, NoxPlayer) since
emulators are often used for automated fraud/credential-stuffing.
MASVS-RESILIENCE-1.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.emulator_detection_static_findings import \
    EMULATOR_DETECTION_STATIC_FINDING_RULES

router = APIRouter()

EMULATOR_MARKERS = [
    # Common emulator props checked at runtime
    b"ro.build.fingerprint", b"generic_x86", b"goldfish",
    b"sdk_gphone", b"google_sdk", b"vbox86",
    b"genymotion", b"Andy", b"droid4x",
    b"bluestacks", b"nox", b"BluestacksApp",
    # Build.HARDWARE checks
    b"ro.hardware", b"ro.product.device", b"emulator",
    # Sensor presence (emulators lack real sensors)
    b"Sensor.TYPE_ACCELEROMETER", b"hasSensor",
    # Files only present on emulators
    b"/dev/qemu_", b"/dev/socket/qemud", b"/system/lib/libc_malloc_debug_qemu.so",
    b"/system/bin/qemud", b"/dev/socket/baseband_genyd",
    # Build.PRODUCT / Build.MODEL checks
    b"Build.PRODUCT", b"Build.HARDWARE", b"Build.FINGERPRINT",
    # iOS simulator
    b"i386", b"x86_64", b"SIMULATOR",
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["emulator_detection_static_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["emulator_detection_static_error"] = str(e); return

    matched = set()
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".so", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for m in EMULATOR_MARKERS:
            if m in data:
                matched.add(m.decode(errors="ignore"))

    ctx.state["emulator_markers_found"] = sorted(matched)
    ctx.state["emulator_detection_static_total"] = len(matched)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} files, {len(matched)} emulator markers")


INTEL_FIELDS = [
    ("Emulator markers found", "emulator_detection_static_total"),
    ("Files scanned",          "files_scanned"),
]


@router.post("/api/mobile_static/emulator_detection_static")
async def mobile_static_emulator_detection_static(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="emulator_detection_static",
        gather_func=gather,
        finding_rules=EMULATOR_DETECTION_STATIC_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
