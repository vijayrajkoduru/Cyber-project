"""realm_coredata_audit - detect Realm DB or iOS CoreData usage without
encryption. Realm has io.realm.RealmConfiguration.Builder.encryptionKey
for encryption; iOS CoreData has NSPersistentStoreFileProtectionKey.
Missing either = sensitive data at rest on disk. MSTG-STORAGE-2."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.realm_coredata_audit_findings import REALM_COREDATA_AUDIT_FINDING_RULES

router = APIRouter()

REALM_USE_RE = re.compile(r"io/realm/(?:Realm|RealmConfiguration)|RealmConfiguration\$Builder")
REALM_ENC_RE = re.compile(r"encryptionKey\(|setEncryptionKey")
COREDATA_RE = re.compile(r"NSPersistentStore|NSManagedObjectContext|CoreData")
COREDATA_PROTECT_RE = re.compile(r"NSPersistentStoreFileProtectionKey|FileProtectionType\.complete")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["realm_coredata_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["realm_coredata_audit_error"] = str(e)
        return

    realm_used = []
    realm_encrypted = False
    coredata_used = []
    coredata_protected = False
    files_scanned = 0

    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        if not p.is_file() or p.suffix not in (".smali", ".plist", ".strings", ".xml"):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        if REALM_USE_RE.search(txt) and len(realm_used) < 15:
            realm_used.append(p.name)
        if REALM_ENC_RE.search(txt):
            realm_encrypted = True
        if COREDATA_RE.search(txt) and len(coredata_used) < 15:
            coredata_used.append(p.name)
        if COREDATA_PROTECT_RE.search(txt):
            coredata_protected = True

    findings_total = 0
    if realm_used and not realm_encrypted:
        findings_total += 1
    if coredata_used and not coredata_protected:
        findings_total += 1

    ctx.state["realm_used"] = realm_used
    ctx.state["realm_encrypted"] = realm_encrypted
    ctx.state["coredata_used"] = coredata_used
    ctx.state["coredata_protected"] = coredata_protected
    ctx.state["files_scanned"] = files_scanned
    ctx.state["realm_coredata_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [
    ("Realm uses", "realm_used"),
    ("Realm encryption set", "realm_encrypted"),
    ("CoreData uses", "coredata_used"),
    ("CoreData protected", "coredata_protected"),
]


@router.post("/api/mobile_storage/realm_coredata_audit")
async def mobile_storage_realm_coredata_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="realm_coredata_audit",
        gather_func=gather,
        finding_rules=REALM_COREDATA_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
