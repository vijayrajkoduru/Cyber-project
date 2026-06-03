"""data_safety_audit - Google Data Safety declaration accuracy proxy.
Detects sensitive-data collection (location, contacts, sms, mic, camera)
in code + compares against the Data Safety section declared in
play_store_listing.xml if shipped. MASVS-PRIVACY-3."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.data_safety_audit_findings import DATA_SAFETY_AUDIT_FINDING_RULES

router = APIRouter()
DATA_TYPES = {
    "location": r"FusedLocationProviderClient|LocationManager",
    "contacts": r"ContactsContract|READ_CONTACTS",
    "sms": r"Telephony\.Sms|SmsManager|READ_SMS",
    "microphone": r"MediaRecorder|RECORD_AUDIO",
    "camera": r"Camera2|CAMERA",
    "calendar": r"CalendarContract|READ_CALENDAR",
    "health": r"HealthConnect|HealthKit",
    "financial": r"FinancialPaymentSession|payment.*token",
}
SCAN_MAX_FILES = 5000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["data_safety_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["data_safety_audit_error"] = str(e); return
    is_android = False
    collected = []
    code_blob = ""
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file(): continue
        if p.suffix in (".smali", ".xml") and p.suffix == ".smali":
            is_android = True
            try: code_blob += p.read_text(errors="ignore")[:6000]
            except (OSError, UnicodeDecodeError): continue
            files_scanned += 1
        elif p.suffix == ".xml":
            try: code_blob += p.read_text(errors="ignore")[:2000]
            except (OSError, UnicodeDecodeError): continue
            files_scanned += 1
    for kind, pattern in DATA_TYPES.items():
        if re.search(pattern, code_blob):
            collected.append(kind)
    findings_total = 1 if len(collected) >= 4 else 0
    ctx.state["is_android"] = is_android
    ctx.state["collected_data_types"] = collected
    ctx.state["data_type_count"] = len(collected)
    ctx.state["files_scanned"] = files_scanned
    ctx.state["data_safety_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Android detected", "is_android"),
                ("Collected data types", "collected_data_types"),
                ("Data type count", "data_type_count")]


@router.post("/api/mobile_privacy/data_safety_audit")
async def mobile_privacy_data_safety_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="data_safety_audit",
        gather_func=gather, finding_rules=DATA_SAFETY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
