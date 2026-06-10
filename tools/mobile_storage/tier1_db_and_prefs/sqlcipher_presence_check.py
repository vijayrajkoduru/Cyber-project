"""sqlcipher_presence_check — verify encrypted-at-rest DB is used.
Looks for net.sqlcipher / SQLCipher / Room+SafeHelperFactory / Realm
encryption-enabled. Positive when present."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.sqlcipher_presence_check_findings import SQLCIPHER_PRESENCE_CHECK_FINDING_RULES

router = APIRouter()

ENCRYPTED_DB_MARKERS = [
    "net/sqlcipher", "net.sqlcipher",
    "SafeHelperFactory",
    "RoomDatabase$Builder", "openHelperFactory",
    "encryptionKey",
    "io/realm/RealmConfiguration", "RealmConfiguration$Builder",
]
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["sqlcipher_presence_check_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["sqlcipher_presence_check_error"] = str(e)
        return

    hits = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for m in ENCRYPTED_DB_MARKERS:
            if m in txt:
                hits.setdefault(m, []).append(p.name)
                if len(hits[m]) > 10:
                    hits[m] = hits[m][:10]

    # Also check libs/ for sqlcipher .so
    sqlcipher_libs = []
    for lib in (unpacked / "lib").rglob("*sqlcipher*"):
        sqlcipher_libs.append(lib.name)

    ctx.state["encryption_markers"] = hits
    ctx.state["sqlcipher_libs"] = sqlcipher_libs
    ctx.state["files_scanned"] = files_scanned
    ctx.state["sqlcipher_presence_check_total"] = 1 if (hits or sqlcipher_libs) else 0
    ctx.source(f"{files_scanned} smali + {len(sqlcipher_libs)} libs")


INTEL_FIELDS = [
    ("Encryption markers", "encryption_markers"),
    ("SQLCipher native libs", "sqlcipher_libs"),
]


@router.post("/api/mobile_storage/sqlcipher_presence_check")
async def mobile_storage_sqlcipher_presence_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="sqlcipher_presence_check",
        gather_func=gather,
        finding_rules=SQLCIPHER_PRESENCE_CHECK_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
