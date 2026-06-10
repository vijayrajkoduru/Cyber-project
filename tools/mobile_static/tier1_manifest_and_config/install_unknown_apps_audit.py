"""install_unknown_apps_audit — REQUEST_INSTALL_PACKAGES perm check.

Apps with REQUEST_INSTALL_PACKAGES can prompt the user to install OTHER
APKs (sideload pipeline). Legitimate use: Amazon Appstore, Samsung
Galaxy Store, F-Droid client. Anything else: high-suspicion sideload
abuse pipeline used by adware / fake-app-store malware.

MASVS-PLATFORM-1.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.install_unknown_apps_audit_findings import \
    INSTALL_UNKNOWN_APPS_AUDIT_FINDING_RULES

router = APIRouter()
NS_A = "{http://schemas.android.com/apk/res/android}"


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["install_unknown_apps_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["install_unknown_apps_audit_error"] = str(e); return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["install_unknown_apps_audit_total"] = 0
        ctx.source("not-android"); return
    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["install_unknown_apps_audit_error"] = "manifest-not-parseable"; return

    risky_perms = []
    for p in root.findall("uses-permission"):
        name = p.get(f"{NS_A}name") or ""
        if name in ("android.permission.REQUEST_INSTALL_PACKAGES",
                     "android.permission.INSTALL_PACKAGES",
                     "android.permission.DELETE_PACKAGES",
                     "android.permission.REQUEST_DELETE_PACKAGES"):
            risky_perms.append(name)

    ctx.state["sideload_perms"] = risky_perms
    ctx.state["install_unknown_apps_audit_total"] = len(risky_perms)
    ctx.source(f"{len(risky_perms)} sideload-related perms")


INTEL_FIELDS = [
    ("Sideload-related perms", "install_unknown_apps_audit_total"),
]


@router.post("/api/mobile_static/install_unknown_apps_audit")
async def mobile_static_install_unknown_apps_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="install_unknown_apps_audit",
        gather_func=gather,
        finding_rules=INSTALL_UNKNOWN_APPS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
