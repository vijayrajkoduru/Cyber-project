"""constant_time_compare_audit - secret comparison via timing-safe APIs.

String.equals / strcmp / Arrays.equals on HMAC / token / nonce permit
timing attacks. Should use MessageDigest.isEqual (Java) /
CryptoKit constant-time / CCOK_constant_time_isequal (BoringSSL).
MSTG-CRYPTO-2."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.constant_time_compare_audit_findings import CONSTANT_TIME_COMPARE_AUDIT_FINDING_RULES

router = APIRouter()
UNSAFE_COMPARE_RE = re.compile(r'String\.equals|Arrays\.equals|\bstrcmp\(|memcmp\(|isEqualToString:|==\s*"?[A-Za-z0-9+/=]{16,}"?')
SAFE_COMPARE_RE = re.compile(r'MessageDigest\.isEqual|constant_time_isequal|CRYPTO_memcmp|ct_memequal')
SECRET_HINTS = ("hmac", "token", "secret", "tag", "nonce", "signature", "mac",
                "hash", "digest", "challenge", "otp")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["constant_time_compare_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["constant_time_compare_audit_error"] = str(e); return
    unsafe_co = []
    safe_count = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".mm", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if SAFE_COMPARE_RE.search(txt): safe_count += 1
        if UNSAFE_COMPARE_RE.search(txt) and any(h in txt.lower() for h in SECRET_HINTS):
            if len(unsafe_co) < 25 and p.name not in unsafe_co:
                unsafe_co.append(p.name)
    findings_total = 1 if unsafe_co else 0
    ctx.state["unsafe_compare_with_secret_keywords"] = unsafe_co
    ctx.state["safe_compare_users"] = safe_count
    ctx.state["files_scanned"] = files_scanned
    ctx.state["constant_time_compare_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Unsafe compare + secret co-located", "unsafe_compare_with_secret_keywords"),
                ("Safe-compare users", "safe_compare_users")]


@router.post("/api/mobile_crypto/constant_time_compare_audit")
async def mobile_crypto_constant_time_compare_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="constant_time_compare_audit",
        gather_func=gather, finding_rules=CONSTANT_TIME_COMPARE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
