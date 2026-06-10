"""device_admin_perm_audit — Device Admin / Device Owner / Profile Owner check.

Device Admin permissions (BIND_DEVICE_ADMIN) let an app: lock the device,
wipe data, force-change password, disable camera. Cerberus and other
banking trojans abuse this to lock out users when detection imminent.

Legitimate use: MDM (Intune, MobileIron, AirWatch). Anything else =
high suspicion.

MASVS-PLATFORM-1.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.device_admin_perm_audit_findings import \
    DEVICE_ADMIN_PERM_AUDIT_FINDING_RULES

router = APIRouter()
NS_A = "{http://schemas.android.com/apk/res/android}"


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["device_admin_perm_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["device_admin_perm_audit_error"] = str(e); return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["device_admin_perm_audit_total"] = 0
        ctx.source("not-android"); return
    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["device_admin_perm_audit_error"] = "manifest-not-parseable"; return

    admin_receivers = []
    app = root.find("application")
    if app is not None:
        for r in app.findall("receiver"):
            perm = r.get(f"{NS_A}permission") or ""
            if perm == "android.permission.BIND_DEVICE_ADMIN":
                name = r.get(f"{NS_A}name") or "?"
                meta_data = []
                for meta in r.findall("meta-data"):
                    mname = meta.get(f"{NS_A}name") or ""
                    mres = meta.get(f"{NS_A}resource") or meta.get(f"{NS_A}value") or ""
                    meta_data.append({"name": mname, "value": mres})
                admin_receivers.append({"name": name, "meta": meta_data})

    ctx.state["device_admin_receivers"] = admin_receivers
    ctx.state["device_admin_perm_audit_total"] = len(admin_receivers)
    ctx.source(f"{len(admin_receivers)} device-admin receiver(s)")


INTEL_FIELDS = [
    ("Device admin receivers", "device_admin_perm_audit_total"),
]


@router.post("/api/mobile_static/device_admin_perm_audit")
async def mobile_static_device_admin_perm_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="device_admin_perm_audit",
        gather_func=gather,
        finding_rules=DEVICE_ADMIN_PERM_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
