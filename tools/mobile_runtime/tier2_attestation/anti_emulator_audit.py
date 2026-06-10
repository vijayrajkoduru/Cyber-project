"""anti_emulator_audit — detect emulator-detection code patterns.
Common: Build.FINGERPRINT/MODEL/MANUFACTURER checks, sensor count,
TelephonyManager device ID. Most checks are trivial to spoof via
MagiskHide / props edits."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.anti_emulator_audit_findings import ANTI_EMULATOR_AUDIT_FINDING_RULES

router = APIRouter()

EMULATOR_MARKERS = {
    "Build.FINGERPRINT":            ['"generic"', '"vbox86"', "FINGERPRINT", "Build->FINGERPRINT"],
    "Build.MODEL":                  ['"sdk"', '"google_sdk"', '"Emulator"', '"Android SDK built for x86"'],
    "Build.MANUFACTURER":           ['"Genymotion"', '"unknown"', "MANUFACTURER"],
    "Build.HARDWARE":               ['"goldfish"', '"ranchu"', '"vbox86"', "HARDWARE"],
    "Build.PRODUCT":                ['"sdk"', '"vbox86p"', '"google_sdk"', "PRODUCT"],
    "QEMU files":                   ['"/proc/cpuinfo"', '"goldfish"', '"/dev/socket/qemud"'],
    "SensorManager check":          ["SensorManager", "getSensorList"],
    "TelephonyManager getDeviceId": ["getDeviceId", "TelephonyManager"],
}
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["anti_emulator_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["anti_emulator_audit_error"] = str(e)
        return

    mechanisms = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for mech_name, markers in EMULATOR_MARKERS.items():
            for m in markers:
                if m in txt:
                    mechanisms.setdefault(mech_name, [])
                    if len(mechanisms[mech_name]) < 5 and p.name not in mechanisms[mech_name]:
                        mechanisms[mech_name].append(p.name)
                    break

    ctx.state["emulator_detection_mechanisms"] = mechanisms
    ctx.state["files_scanned"] = files_scanned
    ctx.state["anti_emulator_audit_total"] = len(mechanisms)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Emulator-detection mechanisms", "emulator_detection_mechanisms"),
]


@router.post("/api/mobile_runtime/anti_emulator_audit")
async def mobile_runtime_anti_emulator_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="anti_emulator_audit",
        gather_func=gather,
        finding_rules=ANTI_EMULATOR_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
