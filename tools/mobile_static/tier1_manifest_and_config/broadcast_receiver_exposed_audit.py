"""broadcast_receiver_exposed_audit — exported BroadcastReceiver review.

Exported broadcast receivers without permission can be triggered by ANY
installed app — sending fake intents to trigger sensitive flows (e.g.
fake 'logout' broadcast → DoS, fake 'sync_now' → repeated billing).
MASVS-PLATFORM-2.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.broadcast_receiver_exposed_audit_findings import \
    BROADCAST_RECEIVER_EXPOSED_AUDIT_FINDING_RULES

router = APIRouter()
NS_A = "{http://schemas.android.com/apk/res/android}"

# System-defined actions that don't need protection (Android handles dispatch)
SYSTEM_PROTECTED = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.TIMEZONE_CHANGED",
    "com.google.android.c2dm.intent.RECEIVE",  # FCM
    "com.google.firebase.MESSAGING_EVENT",
}


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["broadcast_receiver_exposed_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["broadcast_receiver_exposed_audit_error"] = str(e); return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["broadcast_receiver_exposed_audit_total"] = 0
        ctx.source("not-android"); return
    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["broadcast_receiver_exposed_audit_error"] = "manifest-not-parseable"; return

    receivers = []
    risky = []
    app = root.find("application")
    if app is None:
        ctx.state["broadcast_receiver_exposed_audit_total"] = 0
        ctx.source("no-application"); return

    for r in app.findall("receiver"):
        name = r.get(f"{NS_A}name") or "?"
        exported = r.get(f"{NS_A}exported")
        perm = r.get(f"{NS_A}permission")
        # Get the actions on intent-filters
        actions = []
        for ifilter in r.findall("intent-filter"):
            for action in ifilter.findall("action"):
                a = action.get(f"{NS_A}name")
                if a: actions.append(a)
        entry = {"name": name, "exported": exported, "permission": perm,
                  "actions": actions}
        receivers.append(entry)
        # Risky if explicitly exported OR has intent-filter (implicit-export pre-31)
        is_exported = exported == "true" or (exported is None and actions)
        # And no permission AND no system-protected actions
        all_system = actions and all(a in SYSTEM_PROTECTED for a in actions)
        if is_exported and not perm and not all_system:
            risky.append(entry)

    ctx.state["all_receivers"] = receivers
    ctx.state["risky_receivers"] = risky
    ctx.state["broadcast_receiver_exposed_audit_total"] = len(risky)
    ctx.source(f"{len(receivers)} receivers, {len(risky)} risky")


INTEL_FIELDS = [
    ("Risky exported receivers", "broadcast_receiver_exposed_audit_total"),
    ("Total receivers",          "all_receivers"),
]


@router.post("/api/mobile_static/broadcast_receiver_exposed_audit")
async def mobile_static_broadcast_receiver_exposed_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="broadcast_receiver_exposed_audit",
        gather_func=gather,
        finding_rules=BROADCAST_RECEIVER_EXPOSED_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
