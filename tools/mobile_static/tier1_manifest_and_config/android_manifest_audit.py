"""android_manifest_audit — parse AndroidManifest.xml for risky flags."""
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.android_manifest_audit_findings import ANDROID_MANIFEST_AUDIT_FINDING_RULES

router = APIRouter()

NS = {"a": "http://schemas.android.com/apk/res/android"}


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["android_manifest_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["android_manifest_audit_error"] = str(e)
        return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["android_manifest_audit_total"] = 0
        ctx.source("no-manifest")
        return

    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["android_manifest_audit_error"] = "manifest-not-parseable"
        return

    app = root.find("application")
    findings_total = 0
    if app is not None:
        if app.get(f"{{{NS['a']}}}debuggable") == "true":
            ctx.state["debuggable"] = True
            findings_total += 1
        if app.get(f"{{{NS['a']}}}allowBackup") == "true":
            ctx.state["allow_backup"] = True
            findings_total += 1

        exported = []
        for tag in ("activity", "service", "receiver", "provider"):
            for el in app.findall(tag):
                name = el.get(f"{{{NS['a']}}}name") or "?"
                exp = el.get(f"{{{NS['a']}}}exported")
                perm = el.get(f"{{{NS['a']}}}permission")
                if exp == "true" and not perm:
                    exported.append({"name": name, "type": tag})
        if exported:
            ctx.state["exported_components"] = exported
            findings_total += len(exported)

    # Permissions
    perms = [p.get(f"{{{NS['a']}}}name", "?") for p in root.findall("uses-permission")]
    dangerous = [p for p in perms if p.startswith("android.permission.") and any(
        d in p for d in ("READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
                          "RECORD_AUDIO", "READ_CALL_LOG", "CAMERA"))]
    if dangerous:
        ctx.state["dangerous_permissions"] = dangerous
        findings_total += len(dangerous)

    ctx.state["android_manifest_audit_total"] = findings_total
    ctx.source("AndroidManifest.xml")


INTEL_FIELDS = [
    ("Risky flags + components", "android_manifest_audit_total"),
]


@router.post("/api/mobile_static/android_manifest_audit")
async def mobile_static_android_manifest_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="android_manifest_audit",
        gather_func=gather,
        finding_rules=ANDROID_MANIFEST_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
