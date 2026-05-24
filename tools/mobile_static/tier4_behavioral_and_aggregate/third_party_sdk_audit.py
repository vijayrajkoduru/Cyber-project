"""third_party_sdk_audit — enumerate bundled 3rd-party SDKs in APK package tree."""
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.third_party_sdk_audit_findings import THIRD_PARTY_SDK_AUDIT_FINDING_RULES

router = APIRouter()

# Common 3rd-party SDK package prefixes (subset of Exodus Privacy DB)
SDK_SIGNATURES = {
    "com/google/firebase":     ("Firebase",           "MEDIUM", "Google analytics + auth + DB"),
    "com/google/android/gms":  ("Google Play Services","INFO",  "Standard Google services"),
    "com/facebook/sdk":        ("Facebook SDK",       "HIGH",   "Tracks users across apps"),
    "com/facebook/appevents":  ("Facebook AppEvents", "HIGH",   "PII transmitted to Meta"),
    "com/google/firebase/analytics": ("Firebase Analytics", "MEDIUM", "User-behavior tracking"),
    "com/crashlytics":         ("Crashlytics",        "LOW",    "Crash reporting"),
    "com/google/firebase/crashlytics": ("Firebase Crashlytics","LOW", "Crash reporting"),
    "com/appsflyer":           ("AppsFlyer",          "HIGH",   "Attribution + tracking"),
    "com/adjust":              ("Adjust",             "HIGH",   "Attribution + tracking"),
    "com/branch/referral":     ("Branch",             "HIGH",   "Deep-link tracking"),
    "com/segment":             ("Segment",            "MEDIUM", "Analytics aggregator"),
    "com/amplitude":           ("Amplitude",          "MEDIUM", "Product analytics"),
    "com/mixpanel":            ("Mixpanel",           "MEDIUM", "Product analytics"),
    "com/onesignal":           ("OneSignal",          "MEDIUM", "Push notifications"),
    "com/google/ads":          ("Google AdMob",       "MEDIUM", "Ad serving"),
    "com/applovin":            ("AppLovin",           "MEDIUM", "Ad mediation"),
    "com/unity3d/ads":         ("Unity Ads",          "MEDIUM", "Ad serving"),
    "com/ironsource":          ("ironSource",         "MEDIUM", "Ad mediation"),
    "com/vungle":              ("Vungle",             "MEDIUM", "Video ads"),
    "io/sentry":               ("Sentry",             "LOW",    "Error tracking"),
    "io/intercom":             ("Intercom",           "LOW",    "Customer support"),
    "com/squareup/okhttp":     ("OkHttp",             "INFO",   "HTTP client (benign)"),
    "retrofit2":               ("Retrofit",           "INFO",   "HTTP client (benign)"),
}


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["third_party_sdk_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["third_party_sdk_audit_error"] = str(e)
        return

    # Walk smali/ and check for SDK package signatures
    detected = []
    seen_prefixes = set()
    for p in unpacked.rglob("*"):
        if not p.is_dir() and p.suffix.lower() != ".smali":
            continue
        rel = str(p.relative_to(unpacked)).replace("\\", "/").lstrip("smali/")
        for prefix, (name, sev, desc) in SDK_SIGNATURES.items():
            if prefix in rel and prefix not in seen_prefixes:
                detected.append({"sdk": name, "package": prefix,
                                  "severity_hint": sev, "description": desc})
                seen_prefixes.add(prefix)

    ctx.state["sdks_detected"] = detected
    ctx.state["third_party_sdk_audit_total"] = len(detected)
    # Track high-risk SDKs (HIGH severity)
    high_risk = [d for d in detected if d["severity_hint"] == "HIGH"]
    ctx.state["high_risk_sdks"] = high_risk
    ctx.source(f"sdk-signature-scan")


INTEL_FIELDS = [
    ("Total SDKs", "third_party_sdk_audit_total"),
    ("High-risk SDKs", "high_risk_sdks"),
]


@router.post("/api/mobile_static/third_party_sdk_audit")
async def mobile_static_third_party_sdk_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="third_party_sdk_audit",
        gather_func=gather,
        finding_rules=THIRD_PARTY_SDK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
