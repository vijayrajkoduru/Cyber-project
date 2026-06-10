"""removable_storage_audit - SD card / shared-storage writes.

Android: getExternalStorageDirectory, WRITE_EXTERNAL_STORAGE,
         Environment.getExternalStoragePublicDirectory bypass scoped
         storage (Android 10+) and expose data to any app with
         READ_EXTERNAL_STORAGE.
MASVS-STORAGE-2 / MSTG-STORAGE-2 / MASVS-PLATFORM-1."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.removable_storage_audit_findings import REMOVABLE_STORAGE_AUDIT_FINDING_RULES

router = APIRouter()

EXT_STORAGE_RE = re.compile(
    r"getExternalStorageDirectory|getExternalStoragePublicDirectory|"
    r"Environment\.getExternalStorageDirectory|"
    r"MediaStore\.[A-Z][a-zA-Z]*\.EXTERNAL_CONTENT_URI"
)
EXT_PERM_RE = re.compile(r"WRITE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE")
SCOPED_STORAGE_RE = re.compile(
    r'requestLegacyExternalStorage="true"|preserveLegacyExternalStorage="true"|'
    r"android:requestLegacyExternalStorage"
)
SENSITIVE_NEAR_EXT = (
    "token", "password", "secret", "auth", "credential", "private", "jwt",
    "session", "api_key", "card", "pin", "vault", "wallet",
)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["removable_storage_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["removable_storage_audit_error"] = str(e)
        return

    ext_writers = []
    ext_permission_files = []
    legacy_external_used = False
    sensitive_co = []
    files_scanned = 0

    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        if not p.is_file() or p.suffix not in (".smali", ".xml"):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        ext_hit = bool(EXT_STORAGE_RE.search(txt))
        if ext_hit:
            if len(ext_writers) < 25:
                ext_writers.append(p.name)
            if any(h in txt.lower() for h in SENSITIVE_NEAR_EXT):
                if len(sensitive_co) < 25 and p.name not in sensitive_co:
                    sensitive_co.append(p.name)

        if EXT_PERM_RE.search(txt):
            if p.name == "AndroidManifest.xml" or "manifest" in p.name.lower():
                if len(ext_permission_files) < 5:
                    ext_permission_files.append(p.name)

        if SCOPED_STORAGE_RE.search(txt):
            legacy_external_used = True

    findings_total = 0
    if sensitive_co:
        findings_total += 1
    elif ext_writers and ext_permission_files:
        findings_total += 1
    if legacy_external_used:
        findings_total += 1

    ctx.state["ext_storage_writers"] = ext_writers
    ctx.state["ext_storage_permission_files"] = ext_permission_files
    ctx.state["legacy_external_storage"] = legacy_external_used
    ctx.state["sensitive_co_located"] = sensitive_co
    ctx.state["files_scanned"] = files_scanned
    ctx.state["removable_storage_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [
    ("External-storage writers", "ext_storage_writers"),
    ("Ext-storage permissions", "ext_storage_permission_files"),
    ("requestLegacyExternalStorage", "legacy_external_storage"),
    ("Sensitive co-located", "sensitive_co_located"),
]


@router.post("/api/mobile_storage/removable_storage_audit")
async def mobile_storage_removable_storage_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="removable_storage_audit",
        gather_func=gather,
        finding_rules=REMOVABLE_STORAGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
