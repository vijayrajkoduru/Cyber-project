"""advertising_id_audit — IDFA / AAID / Google Ad ID usage.

Apple IDFA needs explicit ATT prompt + NSUserTrackingUsageDescription.
Google AAID + AD_ID permission is required for Play Store (since API 33).
Detects use + flags Apple AppTrackingTransparency requirement violations.

MASVS-PRIVACY-2. Apple ATT. Google Ad ID policy.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.advertising_id_audit_findings import \
    ADVERTISING_ID_AUDIT_FINDING_RULES

router = APIRouter()
NS_A = "{http://schemas.android.com/apk/res/android}"

# DEX/Swift markers
USAGE_MARKERS = {
    "google_ad_id":   [b"AdvertisingIdClient", b"getAdvertisingIdInfo"],
    "ios_idfa":       [b"ASIdentifierManager", b"advertisingIdentifier"],
    "ios_att":        [b"ATTrackingManager", b"requestTrackingAuthorization"],
    "android_app_set_id": [b"AppSetIdClient"],
}


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["advertising_id_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["advertising_id_audit_error"] = str(e); return

    usage = {k: False for k in USAGE_MARKERS}
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali", ".plist", ".swift", ".m") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for kind, markers in USAGE_MARKERS.items():
            if not usage[kind]:
                for m in markers:
                    if m in data:
                        usage[kind] = True
                        break

    # Android manifest: com.google.android.gms.permission.AD_ID
    has_ad_id_perm = False
    has_att_purpose_string = False
    manifest = unpacked / "AndroidManifest.xml"
    if manifest.is_file():
        try:
            root = ET.parse(str(manifest)).getroot()
            for p in root.findall("uses-permission"):
                if p.get(f"{NS_A}name") == "com.google.android.gms.permission.AD_ID":
                    has_ad_id_perm = True
        except Exception:
            pass

    # iOS plist: NSUserTrackingUsageDescription
    for plist in unpacked.rglob("Info.plist"):
        try:
            content = plist.read_bytes()[:200_000]
            if b"NSUserTrackingUsageDescription" in content:
                has_att_purpose_string = True
                break
        except Exception:
            continue

    ctx.state["ad_id_usage"] = usage
    ctx.state["android_ad_id_perm"] = has_ad_id_perm
    ctx.state["ios_att_purpose_string"] = has_att_purpose_string
    issues = 0
    if usage["ios_idfa"] and not usage["ios_att"]: issues += 1
    if usage["ios_idfa"] and not has_att_purpose_string: issues += 1
    if usage["google_ad_id"] and not has_ad_id_perm: issues += 1
    ctx.state["advertising_id_audit_total"] = sum(usage.values()) + issues
    ctx.state["compliance_issues"] = issues
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned}, usage={usage}, issues={issues}")


INTEL_FIELDS = [
    ("Ad-ID usage",            "ad_id_usage"),
    ("Android AD_ID perm",     "android_ad_id_perm"),
    ("iOS ATT purpose string", "ios_att_purpose_string"),
    ("Compliance issues",      "compliance_issues"),
]


@router.post("/api/mobile_static/advertising_id_audit")
async def mobile_static_advertising_id_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="advertising_id_audit",
        gather_func=gather,
        finding_rules=ADVERTISING_ID_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
