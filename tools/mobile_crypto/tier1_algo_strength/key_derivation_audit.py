"""key_derivation_audit - PBKDF2 / scrypt / argon2 iteration count check.
OWASP-recommended floors (2023): PBKDF2 600k (SHA-256), scrypt N=2^17,
argon2id m=64MiB t=3. Lower = brute-forceable. MSTG-CRYPTO-4."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.key_derivation_audit_findings import KEY_DERIVATION_AUDIT_FINDING_RULES

router = APIRouter()
PBKDF2_RE = re.compile(r'PBEKeySpec\s*\([^,]+,\s*[^,]+,\s*(\d+)|PBKDF2(?:WithHmacSHA1|WithHmacSHA256)?')
ITER_NUM_RE = re.compile(r'PBEKeySpec\s*\([^,]+,\s*[^,]+,\s*(\d+)')
SCRYPT_RE = re.compile(r'scrypt|Scrypt|SCryptUtil')
ARGON2_RE = re.compile(r'argon2|Argon2|argon2id|Argon2Hasher')
LOW_ITER_RE = re.compile(r'iterations?\s*=\s*(\d+)|iteration_count\s*=\s*(\d+)')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["key_derivation_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["key_derivation_audit_error"] = str(e); return
    pbkdf2_users = []
    low_iteration_files = []
    scrypt_users, argon2_users = [], []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if PBKDF2_RE.search(txt):
            if len(pbkdf2_users) < 20:
                pbkdf2_users.append(p.name)
            for m in ITER_NUM_RE.finditer(txt):
                try:
                    n = int(m.group(1))
                    if 0 < n < 100000:
                        low_iteration_files.append({"file": p.name, "iterations": n})
                except ValueError: pass
            for m in LOW_ITER_RE.finditer(txt):
                try:
                    n = int(m.group(1) or m.group(2))
                    if 0 < n < 100000:
                        low_iteration_files.append({"file": p.name, "iterations": n})
                except (ValueError, TypeError): pass
        if SCRYPT_RE.search(txt) and len(scrypt_users) < 15:
            scrypt_users.append(p.name)
        if ARGON2_RE.search(txt) and len(argon2_users) < 15:
            argon2_users.append(p.name)
    findings_total = 0
    if low_iteration_files:
        findings_total += 1
    elif pbkdf2_users and not (scrypt_users or argon2_users):
        # PBKDF2 in use but couldn't confirm iteration floor
        findings_total += 1
    ctx.state["pbkdf2_users"] = pbkdf2_users
    ctx.state["low_iteration_files"] = low_iteration_files[:20]
    ctx.state["scrypt_users"] = scrypt_users
    ctx.state["argon2_users"] = argon2_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["key_derivation_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("PBKDF2 users", "pbkdf2_users"),
                ("Low-iteration callers", "low_iteration_files"),
                ("scrypt users", "scrypt_users"),
                ("argon2 users", "argon2_users")]


@router.post("/api/mobile_crypto/key_derivation_audit")
async def mobile_crypto_key_derivation_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="key_derivation_audit",
        gather_func=gather, finding_rules=KEY_DERIVATION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
