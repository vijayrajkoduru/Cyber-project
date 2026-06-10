"""icloud_backup_exclusion_audit - NSURLIsExcludedFromBackupKey on iOS.

Files in Documents/ + Library/Application Support get iCloud-backed up
unless URL.setResourceValue(NSURLIsExcludedFromBackupKey, true).
Sensitive caches must opt out. MSTG-STORAGE-8."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.icloud_backup_exclusion_audit_findings import ICLOUD_BACKUP_EXCLUSION_AUDIT_FINDING_RULES

router = APIRouter()
DOC_WRITE_RE = re.compile(r'NSDocumentDirectory|FileManager\.\.urls\(for:\s*\.documentDirectory|NSApplicationSupportDirectory|applicationSupportDirectory')
EXCLUDE_RE = re.compile(r'NSURLIsExcludedFromBackupKey|isExcludedFromBackup\s*=\s*true|setResourceValue.*?excludedFromBackup')
SENSITIVE_HINTS = ("token", "password", "secret", "auth", "credential",
                    "cache", "tmp", "private", "key", "vault")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["icloud_backup_exclusion_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["icloud_backup_exclusion_audit_error"] = str(e); return
    doc_writers = []
    exclude_callers = 0
    sensitive_co = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".swift", ".m", ".mm", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if DOC_WRITE_RE.search(txt):
            if len(doc_writers) < 25:
                doc_writers.append(p.name)
            if any(h in txt.lower() for h in SENSITIVE_HINTS):
                if len(sensitive_co) < 25 and p.name not in sensitive_co:
                    sensitive_co.append(p.name)
        if EXCLUDE_RE.search(txt): exclude_callers += 1
    findings_total = 0
    if sensitive_co and exclude_callers == 0:
        findings_total += 1
    elif doc_writers and exclude_callers == 0:
        findings_total += 1
    ctx.state["doc_writers"] = doc_writers
    ctx.state["backup_exclude_callers"] = exclude_callers
    ctx.state["sensitive_co_located"] = sensitive_co
    ctx.state["files_scanned"] = files_scanned
    ctx.state["icloud_backup_exclusion_audit_total"] = findings_total
    ctx.source(f"{files_scanned} iOS files")


INTEL_FIELDS = [("Documents/AppSupport writers", "doc_writers"),
                ("setExcludedFromBackup callers", "backup_exclude_callers"),
                ("Sensitive co-located", "sensitive_co_located")]


@router.post("/api/mobile_storage/icloud_backup_exclusion_audit")
async def mobile_storage_icloud_backup_exclusion_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="icloud_backup_exclusion_audit",
        gather_func=gather, finding_rules=ICLOUD_BACKUP_EXCLUSION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
