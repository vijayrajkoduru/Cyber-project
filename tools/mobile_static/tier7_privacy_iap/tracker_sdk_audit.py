"""tracker_sdk_audit — detect bundled analytics/tracking SDKs.

Scans DEX bytecode + resource files for class-prefix signatures of known
analytics/attribution/marketing SDKs. Useful for privacy disclosures (DSA
/ GDPR / iOS App Privacy nutrition labels) and supply-chain risk.

MASVS-PRIVACY-3 / MSTG-PRIVACY-3.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.tracker_sdk_audit_findings import \
    TRACKER_SDK_AUDIT_FINDING_RULES

router = APIRouter()

# (sdk_name, category, byte-marker that uniquely identifies it)
TRACKERS = [
    # Analytics
    ("Firebase Analytics",  "analytics",   b"Lcom/google/firebase/analytics/"),
    ("Google Analytics 4",  "analytics",   b"Lcom/google/android/gms/analytics/"),
    ("Mixpanel",            "analytics",   b"Lcom/mixpanel/android/"),
    ("Amplitude",           "analytics",   b"Lcom/amplitude/api/"),
    ("Segment",              "analytics",   b"Lcom/segment/analytics/"),
    ("Heap Analytics",      "analytics",   b"Lcom/heapanalytics/android/"),
    ("Flurry",              "analytics",   b"Lcom/flurry/android/"),
    # Crash reporting (often analytics-bundled)
    ("Firebase Crashlytics","crash",       b"Lcom/google/firebase/crashlytics/"),
    ("Bugsnag",             "crash",       b"Lcom/bugsnag/android/"),
    ("Sentry",              "crash",       b"Lio/sentry/"),
    # Attribution / marketing
    ("AppsFlyer",           "attribution", b"Lcom/appsflyer/"),
    ("Adjust",              "attribution", b"Lcom/adjust/sdk/"),
    ("Branch",              "attribution", b"Lio/branch/referral/"),
    ("Singular",            "attribution", b"Lcom/singular/sdk/"),
    ("Kochava",             "attribution", b"Lcom/kochava/base/"),
    # Ad networks
    ("Google AdMob",        "advertising", b"Lcom/google/android/gms/ads/"),
    ("Meta (Facebook) Ads", "advertising", b"Lcom/facebook/ads/"),
    ("Unity Ads",           "advertising", b"Lcom/unity3d/ads/"),
    ("AppLovin",            "advertising", b"Lcom/applovin/sdk/"),
    ("IronSource",          "advertising", b"Lcom/ironsource/sdk/"),
    # Push / engagement
    ("OneSignal",           "engagement",  b"Lcom/onesignal/"),
    ("Braze (formerly Appboy)", "engagement", b"Lcom/braze/"),
    ("CleverTap",           "engagement",  b"Lcom/clevertap/android/"),
    ("MoEngage",            "engagement",  b"Lcom/moengage/"),
    # Session replay (high-PII risk)
    ("FullStory",           "session_replay", b"Lcom/fullstory/instrumentation/"),
    ("LogRocket",           "session_replay", b"Lcom/logrocket/protocol/"),
    ("UXCam",               "session_replay", b"Lcom/uxcam/"),
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["tracker_sdk_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["tracker_sdk_audit_error"] = str(e); return

    found = {}  # category -> [sdks]
    by_sdk = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for name, cat, marker in TRACKERS:
            if marker in data and name not in [s["name"] for s in by_sdk]:
                by_sdk.append({"name": name, "category": cat})
                found.setdefault(cat, []).append(name)

    ctx.state["trackers_found"] = by_sdk
    ctx.state["trackers_by_category"] = found
    ctx.state["tracker_sdk_audit_total"] = len(by_sdk)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} files, {len(by_sdk)} tracker SDK(s) detected")


INTEL_FIELDS = [
    ("Tracker SDKs detected", "tracker_sdk_audit_total"),
    ("Files scanned",         "files_scanned"),
]


@router.post("/api/mobile_static/tracker_sdk_audit")
async def mobile_static_tracker_sdk_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="tracker_sdk_audit",
        gather_func=gather,
        finding_rules=TRACKER_SDK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
