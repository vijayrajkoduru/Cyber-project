"""notification_preview_audit - lockscreen notification content leak.

Android: NotificationCompat.Builder.setVisibility(VISIBILITY_PRIVATE) +
         per-channel setLockscreenVisibility — sensitive contents hidden
         on lockscreen.
iOS:     UNNotificationContent threadIdentifier + setShowsPreviewsOption
         (hideAlways / whenAuthenticated) on UNUserNotificationCenter.
MASVS-STORAGE-3 (don't log/display sensitive on lockscreen)."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.notification_preview_audit_findings import NOTIFICATION_PREVIEW_AUDIT_FINDING_RULES

router = APIRouter()

ANDROID_NOTIF_RE = re.compile(r"NotificationCompat\$Builder|NotificationManager|setSmallIcon|setContentText")
ANDROID_HIDE_RE = re.compile(r"setVisibility\([^)]*VISIBILITY_PRIVATE\)|setLockscreenVisibility\([^)]*VISIBILITY_PRIVATE\)|VISIBILITY_SECRET")
IOS_NOTIF_RE = re.compile(r"UNUserNotificationCenter|UNNotificationContent|UNMutableNotificationContent")
IOS_HIDE_RE = re.compile(r"showsPreviewsOption|UNShowPreviewsSettingNever|UNShowPreviewsSettingWhenAuthenticated|hideAlways")
SENSITIVE_HINTS = ("token", "password", "secret", "otp", "code", "balance",
                    "amount", "card", "transaction", "payment", "auth", "pin")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["notification_preview_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["notification_preview_audit_error"] = str(e)
        return

    android_notif_files = []
    android_hide_files = 0
    ios_notif_files = []
    ios_hide_files = 0
    sensitive_co = []
    files_scanned = 0

    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".mm", ".h"):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        a_notif = ANDROID_NOTIF_RE.search(txt)
        i_notif = IOS_NOTIF_RE.search(txt)

        if a_notif:
            if len(android_notif_files) < 25:
                android_notif_files.append(p.name)
            if ANDROID_HIDE_RE.search(txt):
                android_hide_files += 1
        if i_notif:
            if len(ios_notif_files) < 25:
                ios_notif_files.append(p.name)
            if IOS_HIDE_RE.search(txt):
                ios_hide_files += 1

        if (a_notif or i_notif) and any(h in txt.lower() for h in SENSITIVE_HINTS):
            if len(sensitive_co) < 25 and p.name not in sensitive_co:
                sensitive_co.append(p.name)

    findings_total = 0
    if android_notif_files and android_hide_files == 0:
        findings_total += 1
    if ios_notif_files and ios_hide_files == 0:
        findings_total += 1

    ctx.state["android_notif_files"] = android_notif_files
    ctx.state["android_hide_files"] = android_hide_files
    ctx.state["ios_notif_files"] = ios_notif_files
    ctx.state["ios_hide_files"] = ios_hide_files
    ctx.state["sensitive_notification_co"] = sensitive_co
    ctx.state["files_scanned"] = files_scanned
    ctx.state["notification_preview_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [
    ("Android notification builders", "android_notif_files"),
    ("Android with hide policy", "android_hide_files"),
    ("iOS notification builders", "ios_notif_files"),
    ("iOS with hide policy", "ios_hide_files"),
    ("Sensitive co-located", "sensitive_notification_co"),
]


@router.post("/api/mobile_storage/notification_preview_audit")
async def mobile_storage_notification_preview_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="notification_preview_audit",
        gather_func=gather,
        finding_rules=NOTIFICATION_PREVIEW_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
