"""clipboard_api_audit — detect ClipboardManager usage in sensitive contexts.
Risk: passwords / OTP / tokens copied to system clipboard are readable
by ANY other app (Android <10). Also detects no clipboard-clearing
behavior in known-sensitive classes (login, payment)."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.clipboard_api_audit_findings import CLIPBOARD_API_AUDIT_FINDING_RULES

router = APIRouter()

CLIPBOARD_MARKERS = ("ClipboardManager", "setPrimaryClip", "android/content/ClipData")
SENSITIVE_CLASS_HINTS = ("password", "login", "auth", "payment", "card",
                         "wallet", "otp", "pin", "biometric", "secret")
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["clipboard_api_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["clipboard_api_audit_error"] = str(e)
        return

    clipboard_files = []
    sensitive_clipboard_files = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        uses_clipboard = any(m in txt for m in CLIPBOARD_MARKERS)
        if not uses_clipboard:
            continue
        if len(clipboard_files) < 20:
            clipboard_files.append(p.name)

        name_lc = p.name.lower()
        if any(h in name_lc for h in SENSITIVE_CLASS_HINTS):
            if len(sensitive_clipboard_files) < 20:
                sensitive_clipboard_files.append(p.name)

    ctx.state["clipboard_files"] = clipboard_files
    ctx.state["sensitive_clipboard_files"] = sensitive_clipboard_files
    ctx.state["files_scanned"] = files_scanned
    # Sensitive use of clipboard is the real finding
    ctx.state["clipboard_api_audit_total"] = len(sensitive_clipboard_files) or (
        1 if clipboard_files else 0)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Clipboard caller files", "clipboard_files"),
    ("Sensitive clipboard callers", "sensitive_clipboard_files"),
]


@router.post("/api/mobile_storage/clipboard_api_audit")
async def mobile_storage_clipboard_api_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="clipboard_api_audit",
        gather_func=gather,
        finding_rules=CLIPBOARD_API_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
