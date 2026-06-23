"""exported_activity_audit - Android Activity / Service / Receiver
exported without permission. Catches:
  <activity android:exported="true" ...> with no android:permission
  <service ...> + <receiver ...> same pattern
Drozer + `am start` lets any installed app launch / inject. MASVS-PLATFORM-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.exported_activity_audit_findings import EXPORTED_ACTIVITY_AUDIT_FINDING_RULES
from tools._payloads.mobile._loader import load_json

router = APIRouter()
EXPORTED_RE = re.compile(r'<(activity|service|receiver)\b[^>]*android:exported="true"[^>]*>', re.IGNORECASE)
PERM_RE = re.compile(r'android:permission="')
LAUNCHER_RE = re.compile(r'android\.intent\.category\.LAUNCHER')
# Application-level permission applies to every child component that doesn't
# override it (inherited/group permission). Detect it so we don't flag
# components already gated at the <application> level.
APP_PERM_RE = re.compile(r'<application\b[^>]*android:permission="')
# Known SDK / library component packages: an exported component owned by a
# third-party SDK is the SDK's surface, not the app's vuln. presence != vuln.
SDK_PACKAGE_PREFIXES = (
    "com.google.", "com.facebook.", "com.firebase", "firebase",
    "com.android.", "androidx.", "android.support.", "com.crashlytics",
    "io.branch", "com.adjust", "com.appsflyer", "com.onesignal",
    "com.amazon.", "com.microsoft.", "com.huawei.", "com.unity3d",
    "com.rnfirebase", "io.flutter", "com.facebook.react", "expo.modules",
)
# Sensitive exported-component name hints sourced from the shared AI-curated
# mobile pool; inline tuple is the fallback.
_SENSITIVE_HINTS_FALLBACK = ("login", "pin", "password", "auth", "payment", "card",
                             "transfer", "vault", "checkout", "admin", "settings")
SENSITIVE_HINTS = tuple(
    load_json("sensitive_components", fallback={}).get(
        "hints", _SENSITIVE_HINTS_FALLBACK)
) or _SENSITIVE_HINTS_FALLBACK
SCAN_MAX_FILES = 1000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["exported_activity_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["exported_activity_audit_error"] = str(e); return
    exposed = []
    sensitive_exposed = []
    sdk_skipped = []
    files_scanned = 0
    for p in unpacked.rglob("*.xml"):
        if files_scanned >= SCAN_MAX_FILES: break
        if "AndroidManifest" not in p.name and "manifest" not in p.name.lower(): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        # Inherited permission: if <application> declares android:permission,
        # every child component without its own permission is already gated.
        app_has_perm = bool(APP_PERM_RE.search(txt))
        for m in EXPORTED_RE.finditer(txt):
            block = m.group(0)
            kind = m.group(1)
            is_launcher = LAUNCHER_RE.search(txt[max(0, m.start()-200):m.end()+400]) is not None
            has_perm = bool(PERM_RE.search(block)) or app_has_perm
            name_m = re.search(r'android:name="([^"]+)"', block)
            name = name_m.group(1) if name_m else "(unknown)"
            if has_perm or is_launcher:
                continue
            # SDK / library components are not the app's vuln surface.
            nl = name.lstrip(".").lower()
            if any(nl.startswith(pref) for pref in SDK_PACKAGE_PREFIXES):
                if len(sdk_skipped) < 30:
                    sdk_skipped.append({"kind": kind, "name": name[:80]})
                continue
            entry = {"kind": kind, "name": name[:80]}
            if any(h in name.lower() for h in SENSITIVE_HINTS):
                sensitive_exposed.append(entry)
            else:
                exposed.append(entry)
            if len(exposed) + len(sensitive_exposed) >= 30: break
    findings_total = 0
    if sensitive_exposed: findings_total += 1
    if exposed: findings_total += 1
    ctx.state["exposed_components"] = exposed
    ctx.state["sensitive_exposed_components"] = sensitive_exposed
    ctx.state["sdk_components_skipped"] = sdk_skipped
    ctx.state["files_scanned"] = files_scanned
    ctx.state["exported_activity_audit_total"] = findings_total
    ctx.source(f"{files_scanned} manifests")


INTEL_FIELDS = [("Exported (non-sensitive)", "exposed_components"),
                ("Exported sensitive", "sensitive_exposed_components"),
                ("SDK/library exports (excluded)", "sdk_components_skipped")]


@router.post("/api/mobile_ipc/exported_activity_audit")
async def mobile_ipc_exported_activity_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="exported_activity_audit",
        gather_func=gather, finding_rules=EXPORTED_ACTIVITY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
