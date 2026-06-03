"""permission_overask_audit - manifest permissions declared but not used in code.
Catches CAMERA/LOCATION/CONTACTS asked for but never invoked - signals
over-ask that the user / Play Store / App Store may flag. MASVS-PRIVACY-2."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.permission_overask_audit_findings import PERMISSION_OVERASK_AUDIT_FINDING_RULES

router = APIRouter()
USES_PERM_RE = re.compile(r'<uses-permission[^>]+android:name="([^"]+)"')
PERM_USE_HINTS = {
    "android.permission.CAMERA": [r"Camera2|CameraDevice|UIImagePickerController|AVCaptureDevice"],
    "android.permission.RECORD_AUDIO": [r"AudioRecord|MediaRecorder\.AudioSource|AVAudioRecorder"],
    "android.permission.ACCESS_FINE_LOCATION": [r"FusedLocationProviderClient|LocationManager|CLLocationManager"],
    "android.permission.READ_CONTACTS": [r"ContentResolver.*ContactsContract|CNContactStore"],
    "android.permission.READ_SMS": [r"Telephony\.Sms|SmsManager"],
    "android.permission.READ_PHONE_STATE": [r"TelephonyManager"],
    "android.permission.BLUETOOTH_CONNECT": [r"BluetoothAdapter|BluetoothManager"],
    "android.permission.BODY_SENSORS": [r"SensorManager.*BODY|HealthKit"],
}
SCAN_MAX_FILES = 5000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["permission_overask_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["permission_overask_audit_error"] = str(e); return
    declared, code_blob = [], ""
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file(): continue
        if p.suffix == ".xml" and "manifest" in p.name.lower():
            try: txt = p.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError): continue
            files_scanned += 1
            declared.extend(USES_PERM_RE.findall(txt))
        elif p.suffix in (".smali", ".swift", ".m", ".h"):
            try: code_blob += p.read_text(errors="ignore")[:8000]
            except (OSError, UnicodeDecodeError): continue
            files_scanned += 1
    declared = list(dict.fromkeys(declared))
    overask = []
    for perm in declared:
        hints = PERM_USE_HINTS.get(perm)
        if not hints: continue
        if not any(re.search(h, code_blob) for h in hints):
            overask.append(perm)
    findings_total = 1 if overask else 0
    ctx.state["declared_permissions"] = declared[:30]
    ctx.state["overasked_permissions"] = overask
    ctx.state["files_scanned"] = files_scanned
    ctx.state["permission_overask_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Declared permissions", "declared_permissions"),
                ("Over-asked (declared, not used)", "overasked_permissions")]


@router.post("/api/mobile_privacy/permission_overask_audit")
async def mobile_privacy_permission_overask_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="permission_overask_audit",
        gather_func=gather, finding_rules=PERMISSION_OVERASK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
