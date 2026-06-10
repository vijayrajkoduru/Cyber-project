"""strandhogg_audit — task-hijack vulnerability check (StrandHogg + 2.0).

StrandHogg / StrandHogg 2.0 abuse Android's taskAffinity + launchMode +
allowTaskReparenting to insert a malicious activity into your task stack —
when user reopens app from recents, attacker's activity shows first.
Bank apps tracked in 36+ Play Store malware via this in 2020.

Mitigation: taskAffinity='' (empty), launchMode='singleInstance' or
'singleTask' with android:allowTaskReparenting='false'.

MASVS-PLATFORM-3 / CVE-2020-0096.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.strandhogg_audit_findings import \
    STRANDHOGG_AUDIT_FINDING_RULES

router = APIRouter()
NS_A = "{http://schemas.android.com/apk/res/android}"


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["strandhogg_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["strandhogg_audit_error"] = str(e); return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["strandhogg_audit_total"] = 0
        ctx.source("not-android"); return
    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["strandhogg_audit_error"] = "manifest-not-parseable"; return

    risky = []
    main_launchers = []
    for activity in root.findall(".//activity"):
        name = activity.get(f"{NS_A}name") or "?"
        task_affinity = activity.get(f"{NS_A}taskAffinity")
        launch_mode = activity.get(f"{NS_A}launchMode") or "standard"
        reparent = activity.get(f"{NS_A}allowTaskReparenting")
        # MAIN/LAUNCHER activities are the prime target
        is_main = any(
            (cat.get(f"{NS_A}name") == "android.intent.category.LAUNCHER"
              for ifilter in activity.findall("intent-filter")
              for cat in ifilter.findall("category"))
        )
        if is_main:
            main_launchers.append({
                "name": name,
                "taskAffinity": task_affinity,
                "launchMode": launch_mode,
                "allowTaskReparenting": reparent,
            })
            # Risky combination: standard launchMode + non-empty taskAffinity + reparent allowed
            if launch_mode == "standard" and (task_affinity is None or task_affinity != ""):
                risky.append({"name": name, "launchMode": launch_mode,
                                "taskAffinity": task_affinity or "(default = package)"})

    ctx.state["main_launcher_activities"] = main_launchers
    ctx.state["risky_launcher_configs"]   = risky
    ctx.state["strandhogg_audit_total"]   = len(risky)
    ctx.source(f"{len(main_launchers)} MAIN launcher(s), {len(risky)} risky")


INTEL_FIELDS = [
    ("Risky launcher configs",    "strandhogg_audit_total"),
    ("MAIN launcher activities",  "main_launcher_activities"),
]


@router.post("/api/mobile_static/strandhogg_audit")
async def mobile_static_strandhogg_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="strandhogg_audit",
        gather_func=gather,
        finding_rules=STRANDHOGG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
