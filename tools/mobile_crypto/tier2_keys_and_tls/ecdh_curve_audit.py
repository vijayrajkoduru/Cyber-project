"""ecdh_curve_audit - ECDH key-agreement curve choice.
Distinct from rsa_key_size_audit which checks SIGNING keys; this covers
Diffie-Hellman key AGREEMENT. Catches: 1024-bit DH primes, deprecated
secp192/224 ECDH, missing X25519 / X448 preference. MSTG-CRYPTO-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.ecdh_curve_audit_findings import ECDH_CURVE_AUDIT_FINDING_RULES

router = APIRouter()
ECDH_USE_RE = re.compile(r'KeyAgreement\.getInstance\s*\(\s*"ECDH"|ECDHParameterSpec|EC_KEY_new|SecKeyAlgorithmECDH')
DH_USE_RE = re.compile(r'KeyAgreement\.getInstance\s*\(\s*"DH"|DHParameterSpec|DH_new')
DH_SIZE_RE = re.compile(r'DHParameterSpec\s*\([^,]+,\s*\d+,\s*(\d+)')
WEAK_CURVE_RE = re.compile(r'secp160r1|secp192r1|secp224r1|secp192k1')
MODERN_CURVE_RE = re.compile(r'X25519|X448|Curve25519|Ed25519')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ecdh_curve_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["ecdh_curve_audit_error"] = str(e); return
    ecdh_users, dh_users = [], []
    dh_too_small = []
    weak_curve_users = []
    modern_users = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if ECDH_USE_RE.search(txt) and len(ecdh_users) < 20:
            ecdh_users.append(p.name)
        if DH_USE_RE.search(txt):
            if len(dh_users) < 20: dh_users.append(p.name)
            for m in DH_SIZE_RE.finditer(txt):
                try:
                    sz = int(m.group(1))
                    if 0 < sz < 2048:
                        dh_too_small.append({"file": p.name, "bits": sz})
                except (ValueError, TypeError): pass
        if WEAK_CURVE_RE.search(txt) and len(weak_curve_users) < 20:
            weak_curve_users.append(p.name)
        if MODERN_CURVE_RE.search(txt):
            modern_users += 1
    findings_total = 0
    if dh_too_small: findings_total += 1
    if weak_curve_users and (ecdh_users or dh_users): findings_total += 1
    ctx.state["ecdh_users"] = ecdh_users
    ctx.state["dh_users"] = dh_users
    ctx.state["dh_too_small"] = dh_too_small[:20]
    ctx.state["weak_curve_users"] = weak_curve_users
    ctx.state["modern_curve_callers"] = modern_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["ecdh_curve_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("ECDH users", "ecdh_users"),
                ("DH users", "dh_users"),
                ("DH < 2048", "dh_too_small"),
                ("Weak EC curves", "weak_curve_users"),
                ("X25519 / Ed25519 users", "modern_curve_callers")]


@router.post("/api/mobile_crypto/ecdh_curve_audit")
async def mobile_crypto_ecdh_curve_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="ecdh_curve_audit",
        gather_func=gather, finding_rules=ECDH_CURVE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
