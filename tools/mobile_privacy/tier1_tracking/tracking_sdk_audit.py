"""tracking_sdk_audit - Exodus-style tracker / ad SDK enumeration.
Detects well-known tracker / analytics / ad SDK packages bundled in the
APK/IPA. MASVS-PRIVACY-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.tracking_sdk_audit_findings import TRACKING_SDK_AUDIT_FINDING_RULES

router = APIRouter()
TRACKERS = {
    "Google Firebase Analytics": r"com/google/firebase/analytics|firebase_analytics",
    "Google Crashlytics": r"com/google/firebase/crashlytics|com/crashlytics/android",
    "Google AdMob": r"com/google/android/gms/ads",
    "Facebook Audience": r"com/facebook/ads|facebook/audiencenetwork",
    "Facebook Login": r"com/facebook/login|FacebookSdk",
    "Mixpanel": r"com/mixpanel/",
    "Amplitude": r"com/amplitude/",
    "Segment": r"com/segment/analytics",
    "Branch": r"io/branch/",
    "Adjust": r"com/adjust/sdk",
    "AppsFlyer": r"com/appsflyer/",
    "Kochava": r"com/kochava/",
    "Bugsnag": r"com/bugsnag/",
    "Sentry": r"io/sentry/|SentrySdk",
    "Datadog": r"com/datadog/",
    "Adobe Analytics": r"com/adobe/analytics|AdobeMobile",
    "TikTok Pangle": r"com/bytedance/sdk/openadsdk|com/tiktok/",
    "Tencent Beacon": r"com/tencent/beacon",
    "Yandex Metrica": r"com/yandex/metrica",
    "OneSignal": r"com/onesignal/",
}
SCAN_MAX_FILES = 5000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["tracking_sdk_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["tracking_sdk_audit_error"] = str(e); return
    detected = {}
    files_scanned = 0
    paths_blob = ""
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file(): continue
        paths_blob += str(p) + "\n"
        files_scanned += 1
    for name, pattern in TRACKERS.items():
        if re.search(pattern, paths_blob, re.IGNORECASE):
            detected[name] = True
    findings_total = 1 if len(detected) >= 3 else 0
    ctx.state["detected_trackers"] = sorted(detected.keys())
    ctx.state["tracker_count"] = len(detected)
    ctx.state["files_scanned"] = files_scanned
    ctx.state["tracking_sdk_audit_total"] = findings_total
    ctx.source(f"{files_scanned} paths")


INTEL_FIELDS = [("Detected tracker SDKs", "detected_trackers"),
                ("Tracker count", "tracker_count")]


@router.post("/api/mobile_privacy/tracking_sdk_audit")
async def mobile_privacy_tracking_sdk_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="tracking_sdk_audit",
        gather_func=gather, finding_rules=TRACKING_SDK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
