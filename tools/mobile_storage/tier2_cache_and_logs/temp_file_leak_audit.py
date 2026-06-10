"""temp_file_leak_audit - detect writes to temp / cache locations that
survive the lifecycle and may leak sensitive data.

Android: /data/local/tmp, /data/data/<pkg>/cache, getCacheDir, getExternalCacheDir
iOS:     NSTemporaryDirectory, /tmp/, FileManager.default.temporaryDirectory
MSTG-STORAGE-2 / MSTG-STORAGE-3."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.temp_file_leak_audit_findings import TEMP_FILE_LEAK_AUDIT_FINDING_RULES

router = APIRouter()

ANDROID_TEMP_RE = re.compile(
    r"/data/local/tmp|getCacheDir|getExternalCacheDir|/cache/|FileOutputStream\s*\([^)]*cache"
)
IOS_TEMP_RE = re.compile(
    r"NSTemporaryDirectory|temporaryDirectory|/tmp/|writeToFile.*tmp"
)
SENSITIVE_NEAR_TEMP = (
    "token", "password", "secret", "auth", "credential", "private", "jwt",
    "session", "api_key", "card", "pin",
)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["temp_file_leak_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["temp_file_leak_audit_error"] = str(e)
        return

    android_temp_files = []
    ios_temp_files = []
    co_located_sensitive = []
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

        a_hit = bool(ANDROID_TEMP_RE.search(txt))
        i_hit = bool(IOS_TEMP_RE.search(txt))
        if a_hit and len(android_temp_files) < 20:
            android_temp_files.append(p.name)
        if i_hit and len(ios_temp_files) < 20:
            ios_temp_files.append(p.name)
        if (a_hit or i_hit) and any(h in txt.lower() for h in SENSITIVE_NEAR_TEMP):
            if len(co_located_sensitive) < 20 and p.name not in co_located_sensitive:
                co_located_sensitive.append(p.name)

    findings_total = 0
    if co_located_sensitive:
        findings_total += 1
    elif android_temp_files or ios_temp_files:
        findings_total += 1

    ctx.state["android_temp_files"] = android_temp_files
    ctx.state["ios_temp_files"] = ios_temp_files
    ctx.state["co_located_sensitive"] = co_located_sensitive
    ctx.state["files_scanned"] = files_scanned
    ctx.state["temp_file_leak_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [
    ("Android temp writers", "android_temp_files"),
    ("iOS temp writers", "ios_temp_files"),
    ("Sensitive co-located with temp", "co_located_sensitive"),
]


@router.post("/api/mobile_storage/temp_file_leak_audit")
async def mobile_storage_temp_file_leak_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="temp_file_leak_audit",
        gather_func=gather,
        finding_rules=TEMP_FILE_LEAK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
