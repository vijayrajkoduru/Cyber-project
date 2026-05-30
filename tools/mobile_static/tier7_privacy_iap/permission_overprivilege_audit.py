"""permission_overprivilege_audit — flag apps requesting more perms than they need.

Parses AndroidManifest for uses-permission entries and emits findings for
the "over-permissioned" anti-pattern: apps requesting dangerous permissions
(LOCATION, CAMERA, READ_SMS, etc.) when they appear unrelated to the app's
declared purpose. Output is advisory — full overprivilege analysis needs
human review of actual use cases.

MASVS-PRIVACY-1 / MSTG-PRIVACY-1.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.permission_overprivilege_audit_findings import \
    PERMISSION_OVERPRIVILEGE_AUDIT_FINDING_RULES

router = APIRouter()

NS_A = "{http://schemas.android.com/apk/res/android}"

# Dangerous permissions (Android 11 grouping) — these need runtime consent
# and are commonly over-requested
DANGEROUS_PERMS = {
    "android.permission.READ_SMS":           "SMS body read",
    "android.permission.RECEIVE_SMS":        "SMS receive",
    "android.permission.SEND_SMS":           "SMS send",
    "android.permission.READ_CALL_LOG":      "call log read",
    "android.permission.WRITE_CALL_LOG":     "call log write",
    "android.permission.READ_CONTACTS":      "contacts read",
    "android.permission.WRITE_CONTACTS":     "contacts write",
    "android.permission.ACCESS_FINE_LOCATION":     "precise location",
    "android.permission.ACCESS_COARSE_LOCATION":   "coarse location",
    "android.permission.ACCESS_BACKGROUND_LOCATION":"background location",
    "android.permission.RECORD_AUDIO":       "microphone record",
    "android.permission.CAMERA":             "camera",
    "android.permission.BODY_SENSORS":       "health sensors",
    "android.permission.READ_PHONE_STATE":   "device/SIM/IMEI",
    "android.permission.READ_PHONE_NUMBERS": "phone number",
    "android.permission.READ_MEDIA_IMAGES":  "photo library",
    "android.permission.READ_MEDIA_VIDEO":   "video library",
    "android.permission.GET_ACCOUNTS":       "account list",
    "android.permission.ACCESS_NOTIFICATION_POLICY": "DND control",
    "android.permission.QUERY_ALL_PACKAGES": "installed-app list",
}

# Permissions that are signature-level / privileged — should NEVER appear in
# third-party apps
PRIVILEGED_PERMS = [
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.MANAGE_USERS",
    "android.permission.READ_LOGS",
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["permission_overprivilege_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["permission_overprivilege_audit_error"] = str(e); return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        # iOS / non-Android
        ctx.state["permission_overprivilege_audit_total"] = 0
        ctx.source("not-android"); return

    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["permission_overprivilege_audit_error"] = "manifest-not-parseable"
        return

    perms = [p.get(f"{NS_A}name") or "" for p in root.findall("uses-permission")]
    total = len(perms)
    dangerous_found = [p for p in perms if p in DANGEROUS_PERMS]
    privileged_found = [p for p in perms if p in PRIVILEGED_PERMS]

    ctx.state["all_permissions"] = perms
    ctx.state["dangerous_permissions"] = dangerous_found
    ctx.state["privileged_permissions"] = privileged_found
    ctx.state["permission_count"] = total
    ctx.state["permission_overprivilege_audit_total"] = (
        len(dangerous_found) + len(privileged_found) * 3)
    ctx.source(f"manifest parsed, {total} uses-permission entries")


INTEL_FIELDS = [
    ("Total permissions",  "permission_count"),
    ("Dangerous found",    "dangerous_permissions"),
    ("Privileged found",   "privileged_permissions"),
]


@router.post("/api/mobile_static/permission_overprivilege_audit")
async def mobile_static_permission_overprivilege_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="permission_overprivilege_audit",
        gather_func=gather,
        finding_rules=PERMISSION_OVERPRIVILEGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
