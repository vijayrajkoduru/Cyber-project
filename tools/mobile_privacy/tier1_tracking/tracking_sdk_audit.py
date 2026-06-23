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
from tools._payloads.mobile._loader import load_json

router = APIRouter()
# Sourced from the shared AI-curated mobile pool (path-style markers); inline
# dict is the fallback so behaviour is identical if the JSON is unavailable.
_TRACKERS_FALLBACK = {
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


def _load_trackers():
    pool = load_json("tracker_sdks", fallback=None)
    if not pool:
        return _TRACKERS_FALLBACK
    out = {}
    for row in pool:
        pat = row.get("path_marker")
        if pat:
            out[row.get("name", "Unknown")] = pat
    return out or _TRACKERS_FALLBACK


TRACKERS = _load_trackers()
SCAN_MAX_FILES = 5000
# presence != active tracking: an SDK on the classpath may be a transitive dep
# that is never initialized. Look for an actual init/usage call site to
# distinguish bundled-but-dormant from actively-tracking.
INIT_MARKERS_RE = re.compile(
    r'\.initialize\s*\(|\.getInstance\s*\(|\.init\s*\(|setAnalyticsCollectionEnabled|'
    r'logEvent\s*\(|trackEvent\s*\(|\.start\s*\(|configureWithOptions|'
    r'FirebaseApp\.initializeApp|\.activate\s*\(|\.setUserId\s*\(|identify\s*\(',
    re.IGNORECASE)
CODE_SUFFIXES = (".smali", ".swift", ".m", ".java", ".js")
CODE_SCAN_MAX = 4000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["tracking_sdk_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["tracking_sdk_audit_error"] = str(e); return
    detected = {}
    files_scanned = 0
    paths_blob = ""
    code_blob = ""
    code_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file(): continue
        paths_blob += str(p) + "\n"
        files_scanned += 1
        if code_scanned < CODE_SCAN_MAX and p.suffix in CODE_SUFFIXES:
            try:
                code_blob += p.read_text(errors="ignore")[:4000]
                code_scanned += 1
            except (OSError, UnicodeDecodeError):
                pass
    for name, pattern in TRACKERS.items():
        if re.search(pattern, paths_blob, re.IGNORECASE):
            detected[name] = True
    # Active vs. dormant: count trackers whose package marker co-occurs with an
    # init/usage call site somewhere in code.
    active = []
    for name, pattern in TRACKERS.items():
        if name not in detected:
            continue
        # Use a lightweight class-name token from the pattern's last path segment.
        token = re.split(r'[\\/|]', pattern)[-1].strip()
        if token and re.search(re.escape(token), code_blob, re.IGNORECASE) and INIT_MARKERS_RE.search(code_blob):
            active.append(name)
    active_count = len(active)
    # Only grade when we see active initialization of multiple trackers;
    # presence-only is downgraded to INFO by the rules.
    findings_total = 1 if (len(detected) >= 3 and active_count >= 1) else 0
    ctx.state["detected_trackers"] = sorted(detected.keys())
    ctx.state["active_trackers"] = sorted(active)
    ctx.state["tracker_count"] = len(detected)
    ctx.state["active_tracker_count"] = active_count
    ctx.state["files_scanned"] = files_scanned
    ctx.state["tracking_sdk_audit_total"] = findings_total
    ctx.source(f"{files_scanned} paths + {code_scanned} code")


INTEL_FIELDS = [("Detected tracker SDKs", "detected_trackers"),
                ("Tracker count", "tracker_count"),
                ("Actively-initialized trackers", "active_trackers"),
                ("Active tracker count", "active_tracker_count")]


@router.post("/api/mobile_privacy/tracking_sdk_audit")
async def mobile_privacy_tracking_sdk_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="tracking_sdk_audit",
        gather_func=gather, finding_rules=TRACKING_SDK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
