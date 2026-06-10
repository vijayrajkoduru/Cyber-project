"""accessibility_service_audit — BIND_ACCESSIBILITY_SERVICE detection.

Apps using BIND_ACCESSIBILITY_SERVICE can read content from ALL other
apps + click on their behalf. This is the #1 vector used by Android
banking trojans (Cerberus, FluBot, BRATA, Anubis) — they trick users
into enabling "accessibility" for them, then drain banking apps.

Legitimate use: password managers (BitWarden, 1Password), screen readers
(TalkBack), text-to-speech apps. Anything else REQUESTING accessibility
service is highly suspect.

MASVS-PLATFORM-7. Banking-trojan-defense KEY signal.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.accessibility_service_audit_findings import \
    ACCESSIBILITY_SERVICE_AUDIT_FINDING_RULES

router = APIRouter()
NS_A = "{http://schemas.android.com/apk/res/android}"


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["accessibility_service_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["accessibility_service_audit_error"] = str(e); return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["accessibility_service_audit_total"] = 0
        ctx.source("not-android"); return
    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["accessibility_service_audit_error"] = "manifest-not-parseable"; return

    a11y_services = []
    app = root.find("application")
    if app is not None:
        for svc in app.findall("service"):
            perm = svc.get(f"{NS_A}permission") or ""
            if perm == "android.permission.BIND_ACCESSIBILITY_SERVICE":
                name = svc.get(f"{NS_A}name") or "?"
                # Look for intent-filter android.accessibilityservice.AccessibilityService
                actions = []
                for ifilter in svc.findall("intent-filter"):
                    for action in ifilter.findall("action"):
                        a = action.get(f"{NS_A}name")
                        if a: actions.append(a)
                a11y_services.append({"name": name, "actions": actions})

    ctx.state["accessibility_services"] = a11y_services
    ctx.state["accessibility_service_audit_total"] = len(a11y_services)
    ctx.source(f"{len(a11y_services)} accessibility service(s)")


INTEL_FIELDS = [
    ("Accessibility services declared", "accessibility_service_audit_total"),
]


@router.post("/api/mobile_static/accessibility_service_audit")
async def mobile_static_accessibility_service_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="accessibility_service_audit",
        gather_func=gather,
        finding_rules=ACCESSIBILITY_SERVICE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
