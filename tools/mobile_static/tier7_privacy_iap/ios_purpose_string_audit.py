"""ios_purpose_string_audit — Info.plist NSXxxUsageDescription audit.

iOS requires Info.plist purpose-strings (NSCameraUsageDescription, etc.)
for every protected resource. Apple rejects apps where strings are:
- missing for declared usage
- generic ('We need this to function' = REJECT)
- not in declared App Privacy Nutrition labels

This scanner inventories all NS*UsageDescription keys + flags short
generic descriptions.

MASVS-PRIVACY-1. App Store Review Guideline 5.1.1.
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.ios_purpose_string_audit_findings import \
    IOS_PURPOSE_STRING_AUDIT_FINDING_RULES

router = APIRouter()

USAGE_KEYS = [
    "NSCameraUsageDescription", "NSMicrophoneUsageDescription",
    "NSPhotoLibraryUsageDescription", "NSPhotoLibraryAddUsageDescription",
    "NSContactsUsageDescription", "NSCalendarsUsageDescription",
    "NSRemindersUsageDescription", "NSLocationWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription", "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSHealthShareUsageDescription", "NSHealthUpdateUsageDescription",
    "NSMotionUsageDescription", "NSFaceIDUsageDescription",
    "NSBluetoothPeripheralUsageDescription", "NSBluetoothAlwaysUsageDescription",
    "NSAppleMusicUsageDescription", "NSSpeechRecognitionUsageDescription",
    "NSSiriUsageDescription", "NSHomeKitUsageDescription",
    "NSUserTrackingUsageDescription", "NSLocalNetworkUsageDescription",
    "NSNearbyInteractionUsageDescription",
    "NSFocusStatusUsageDescription",  # iOS 15+
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ios_purpose_string_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["ios_purpose_string_audit_error"] = str(e); return

    # Find Info.plist
    plists = list(unpacked.rglob("Info.plist"))
    if not plists:
        ctx.state["ios_purpose_string_audit_total"] = 0
        ctx.source("no-info-plist (not iOS)"); return

    main_plist = max(plists, key=lambda p: p.stat().st_size)  # main app plist
    try:
        content = main_plist.read_bytes()[:500_000]
    except Exception as e:
        ctx.state["ios_purpose_string_audit_error"] = str(e); return

    # Parse XML or binary plist
    findings = {}  # key -> description
    try:
        import plistlib
        plist = plistlib.loads(content)
        for key in USAGE_KEYS:
            if key in plist:
                findings[key] = str(plist[key])
    except Exception:
        # Fallback: regex on XML-form plist
        for key in USAGE_KEYS:
            pat = re.compile(
                rf"<key>{key}</key>\s*<string>([^<]*)</string>".encode())
            m = pat.search(content)
            if m:
                findings[key] = m.group(1).decode(errors="ignore")

    # Audit: short / generic strings
    short_strings = {k: v for k, v in findings.items() if len(v) < 30}
    generic_phrases = ("we need", "to function", "to work", "required",
                        "permission", "access", "use this app")
    generic_strings = {k: v for k, v in findings.items()
                        if any(g in v.lower() for g in generic_phrases) and len(v) < 60}

    ctx.state["usage_descriptions"] = findings
    ctx.state["short_descriptions"] = short_strings
    ctx.state["generic_descriptions"] = generic_strings
    ctx.state["ios_purpose_string_audit_total"] = (
        len(short_strings) + len(generic_strings))
    ctx.source(f"{len(findings)} usage strings, {len(short_strings)} short, "
                f"{len(generic_strings)} generic")


INTEL_FIELDS = [
    ("Usage descriptions found", "usage_descriptions"),
    ("Short/weak descriptions",  "short_descriptions"),
    ("Generic descriptions",     "generic_descriptions"),
]


@router.post("/api/mobile_static/ios_purpose_string_audit")
async def mobile_static_ios_purpose_string_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ios_purpose_string_audit",
        gather_func=gather,
        finding_rules=IOS_PURPOSE_STRING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
