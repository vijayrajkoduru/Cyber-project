"""kdf_salt_audit - missing or static salt in KDF.
PBEKeySpec(<password>, <salt>, ...) where salt is hardcoded or zero-byte.
A static salt across all users defeats pre-image resistance + rainbow
tables become viable. MSTG-CRYPTO-4."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.kdf_salt_audit_findings import KDF_SALT_AUDIT_FINDING_RULES

router = APIRouter()
LITERAL_SALT_RE = re.compile(r'PBEKeySpec\s*\([^,]+,\s*"([^"]+)"\.getBytes|PBEKeySpec\s*\([^,]+,\s*new\s+byte\s*\[\s*\d+\s*\]')
SECURE_RANDOM_SALT_RE = re.compile(r'SecureRandom\(\)\.nextBytes|new\s+SecureRandom\(\)\.nextBytes')
KDF_USE_RE = re.compile(r'PBEKeySpec|SecretKeyFactory|HKDFBytesGenerator')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["kdf_salt_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["kdf_salt_audit_error"] = str(e); return
    kdf_users = []
    static_salt_files = []
    random_salt_co = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if KDF_USE_RE.search(txt):
            if len(kdf_users) < 20:
                kdf_users.append(p.name)
            if LITERAL_SALT_RE.search(txt):
                if len(static_salt_files) < 20:
                    static_salt_files.append(p.name)
            if SECURE_RANDOM_SALT_RE.search(txt):
                random_salt_co += 1
    findings_total = 0
    if static_salt_files:
        findings_total += 1
    elif kdf_users and random_salt_co == 0:
        findings_total += 1
    ctx.state["kdf_users"] = kdf_users
    ctx.state["static_salt_files"] = static_salt_files
    ctx.state["random_salt_co_usage"] = random_salt_co
    ctx.state["files_scanned"] = files_scanned
    ctx.state["kdf_salt_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("KDF users", "kdf_users"),
                ("Static / zero salt", "static_salt_files"),
                ("SecureRandom + KDF co-located", "random_salt_co_usage")]


@router.post("/api/mobile_crypto/kdf_salt_audit")
async def mobile_crypto_kdf_salt_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="kdf_salt_audit",
        gather_func=gather, finding_rules=KDF_SALT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
