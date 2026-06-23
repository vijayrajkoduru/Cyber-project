"""sqlite_usage_audit — detect SQLite usage patterns in decompiled APK +
hints at sensitive schema. Flags: plain SQLiteDatabase usage without
SQLCipher, hardcoded DB names suggesting auth/financial data."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.sqlite_usage_audit_findings import SQLITE_USAGE_AUDIT_FINDING_RULES
from tools._payloads.mobile._fp_gates import is_app_code_path

router = APIRouter()

DB_NAME_RE = re.compile(r'"([a-zA-Z0-9_]{3,30}\.db)"')
SENSITIVE_DB_HINTS = ("auth", "user", "wallet", "card", "account", "session",
                      "creds", "secure", "vault", "key", "token", "login")
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["sqlite_usage_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["sqlite_usage_audit_error"] = str(e)
        return

    sqlite_files = []          # all callers (intel)
    app_sqlite_files = []      # callers in APP code only (excludes lib/test)
    sqlcipher_files = []
    db_names = set()
    sensitive_db_names = []
    files_scanned = 0

    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        try:
            rel = str(p.relative_to(unpacked))
        except ValueError:
            rel = p.name
        app_code = is_app_code_path(rel)

        if "SQLiteDatabase" in txt or "SQLiteOpenHelper" in txt:
            if len(sqlite_files) < 20:
                sqlite_files.append(p.name)
            if app_code and len(app_sqlite_files) < 20:
                app_sqlite_files.append(p.name)
            for m in DB_NAME_RE.finditer(txt):
                name = m.group(1)
                db_names.add(name)
                if any(h in name.lower() for h in SENSITIVE_DB_HINTS):
                    if name not in sensitive_db_names:
                        sensitive_db_names.append(name)

        if "net/sqlcipher" in txt or "net.sqlcipher" in txt:
            if len(sqlcipher_files) < 20:
                sqlcipher_files.append(p.name)

    findings_total = 0
    # Only the app's own unencrypted SQLite usage is a real posture finding.
    if app_sqlite_files and not sqlcipher_files:
        findings_total += 1
    # A DB NAME containing "auth"/"wallet"/etc is just a name, not evidence of
    # a sensitive write -> reported at INFO (does not bump findings_total).

    ctx.state["sqlite_files"] = sqlite_files
    ctx.state["app_sqlite_files"] = app_sqlite_files
    ctx.state["sqlcipher_files"] = sqlcipher_files
    ctx.state["db_names"] = sorted(db_names)[:20]
    ctx.state["sensitive_db_names"] = sensitive_db_names
    ctx.state["files_scanned"] = files_scanned
    ctx.state["sqlite_usage_audit_total"] = findings_total
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("SQLite caller files", "sqlite_files"),
    ("SQLite callers in app code", "app_sqlite_files"),
    ("SQLCipher caller files", "sqlcipher_files"),
    ("DB names found", "db_names"),
    ("Sensitive-looking DB names", "sensitive_db_names"),
]


@router.post("/api/mobile_storage/sqlite_usage_audit")
async def mobile_storage_sqlite_usage_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="sqlite_usage_audit",
        gather_func=gather,
        finding_rules=SQLITE_USAGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
