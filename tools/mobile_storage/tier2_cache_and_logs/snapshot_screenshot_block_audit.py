"""snapshot_screenshot_block_audit - iOS counterpart to FLAG_SECURE.

iOS captures a snapshot on backgrounding (for the app-switcher). Sensitive
screens (PIN, payment, vault) must blank or replace the view in
applicationDidEnterBackground or sceneWillResignActive. MASVS-STORAGE
(implementation guidance). Detects iOS apps with sensitive view names
and no blanking lifecycle hook."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.snapshot_screenshot_block_audit_findings import SNAPSHOT_SCREENSHOT_BLOCK_AUDIT_FINDING_RULES

router = APIRouter()

BG_HOOK_RE = re.compile(
    r"applicationDidEnterBackground|sceneWillResignActive|"
    r"applicationWillResignActive|sceneDidEnterBackground"
)
BLANK_RE = re.compile(
    r"isHidden\s*=\s*true|hidden\s*=\s*1|UIBlurEffect|UIVisualEffectView|"
    r"setUserInteractionEnabled.*false|window\.rootViewController.*nil"
)
SENSITIVE_VIEW_HINTS = (
    "login", "pin", "password", "auth", "payment", "card", "vault",
    "wallet", "otp", "biometric", "checkout", "secret",
)
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["snapshot_screenshot_block_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["snapshot_screenshot_block_audit_error"] = str(e)
        return

    is_ios = False
    has_bg_hook = False
    has_blanking = False
    sensitive_views = []
    files_scanned = 0

    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        if not p.is_file() or p.suffix not in (".swift", ".m", ".mm", ".h", ".plist", ".strings"):
            continue
        is_ios = True
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        if BG_HOOK_RE.search(txt):
            has_bg_hook = True
        if BLANK_RE.search(txt):
            has_blanking = True
        name_lc = p.name.lower()
        if any(h in name_lc for h in SENSITIVE_VIEW_HINTS) and len(sensitive_views) < 25:
            sensitive_views.append(p.name)

    findings_total = 0
    if is_ios and sensitive_views and not (has_bg_hook and has_blanking):
        findings_total += 1

    ctx.state["is_ios"] = is_ios
    ctx.state["has_bg_hook"] = has_bg_hook
    ctx.state["has_blanking"] = has_blanking
    ctx.state["sensitive_views"] = sensitive_views
    ctx.state["files_scanned"] = files_scanned
    ctx.state["snapshot_screenshot_block_audit_total"] = findings_total
    ctx.source(f"{files_scanned} ios files")


INTEL_FIELDS = [
    ("iOS sources scanned", "is_ios"),
    ("Background hook present", "has_bg_hook"),
    ("Blanking pattern present", "has_blanking"),
    ("Sensitive views", "sensitive_views"),
]


@router.post("/api/mobile_storage/snapshot_screenshot_block_audit")
async def mobile_storage_snapshot_screenshot_block_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="snapshot_screenshot_block_audit",
        gather_func=gather,
        finding_rules=SNAPSHOT_SCREENSHOT_BLOCK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
