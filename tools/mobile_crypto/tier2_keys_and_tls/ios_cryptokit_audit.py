"""ios_cryptokit_audit - iOS CryptoKit modern usage detection.
CryptoKit (iOS 13+) is the Swift-first safe API. Detects legacy
CommonCrypto / SecKey usage where CryptoKit would be safer +
constant-time by default. MSTG-CRYPTO-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.ios_cryptokit_audit_findings import IOS_CRYPTOKIT_AUDIT_FINDING_RULES

router = APIRouter()
CRYPTOKIT_RE = re.compile(r'import\s+CryptoKit|CryptoKit\.|AES\.GCM\.|ChaChaPoly|Curve25519|SymmetricKey')
COMMONCRYPTO_RE = re.compile(r'import\s+CommonCrypto|CCCryptorCreate|CC_SHA256|CC_HMAC|kCCAlgorithmAES')
SECKEY_RE = re.compile(r'SecKeyCreateRandomKey|SecKeyAlgorithm|SecKeyCreateSignature')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ios_cryptokit_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["ios_cryptokit_audit_error"] = str(e); return
    is_ios = False
    cryptokit_users = []
    commoncrypto_users = []
    seckey_users = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".swift", ".m", ".mm", ".h"): continue
        is_ios = True
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if CRYPTOKIT_RE.search(txt) and len(cryptokit_users) < 20:
            cryptokit_users.append(p.name)
        if COMMONCRYPTO_RE.search(txt) and len(commoncrypto_users) < 20:
            commoncrypto_users.append(p.name)
        if SECKEY_RE.search(txt) and len(seckey_users) < 20:
            seckey_users.append(p.name)
    findings_total = 0
    # Heavy CommonCrypto with no CryptoKit migration = legacy posture
    if is_ios and commoncrypto_users and not cryptokit_users:
        findings_total += 1
    ctx.state["is_ios"] = is_ios
    ctx.state["cryptokit_users"] = cryptokit_users
    ctx.state["commoncrypto_users"] = commoncrypto_users
    ctx.state["seckey_users"] = seckey_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["ios_cryptokit_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("iOS detected", "is_ios"),
                ("CryptoKit users", "cryptokit_users"),
                ("CommonCrypto users", "commoncrypto_users"),
                ("SecKey users", "seckey_users")]


@router.post("/api/mobile_crypto/ios_cryptokit_audit")
async def mobile_crypto_ios_cryptokit_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="ios_cryptokit_audit",
        gather_func=gather, finding_rules=IOS_CRYPTOKIT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
