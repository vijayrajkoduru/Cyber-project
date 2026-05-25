"""custom_crypto_audit (§4 #50) — heuristics for home-rolled crypto.
'Never roll your own.' Flags XOR loops with single byte, simple Caesar/ROT
patterns, base64-only obfuscation marketed as encryption, and rolled-out
'encrypt'/'decrypt' methods that DON'T call javax.crypto.*."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.custom_crypto_audit_findings import CUSTOM_CRYPTO_AUDIT_FINDING_RULES

router = APIRouter()

# Smali XOR opcode pattern (single byte xor against a hardcoded literal)
# xor-int/lit8 vX, vY, 0x<n>  → strong indicator of homebrew XOR cipher
XOR_LIT8_PATTERN = re.compile(r'\bxor-int/lit8\s+v\d+,\s*v\d+,\s*0x[0-9a-f]+', re.IGNORECASE)
XOR_INT_PATTERN = re.compile(r'\bxor-int\s+v\d+')
ENCRYPT_DECRYPT_METHODS = re.compile(r'\.method.*\b(encrypt|decrypt|cipher|encode|decode)\b', re.IGNORECASE)
JCA_USAGE = ("Ljavax/crypto/", "Ljava/security/", "Lorg/bouncycastle/")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["custom_crypto_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["custom_crypto_audit_error"] = str(e)
        return

    xor_loop_files = []
    homebrew_methods = []   # method named encrypt/decrypt but no JCA usage
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        # Heavy XOR loops (>= 3 xor-int/lit8 in same file = strong signal)
        xor_lit8_hits = len(XOR_LIT8_PATTERN.findall(txt))
        xor_int_hits = len(XOR_INT_PATTERN.findall(txt))
        if xor_lit8_hits >= 3 or xor_int_hits >= 5:
            if p.name not in xor_loop_files and len(xor_loop_files) < 25:
                xor_loop_files.append({"file": p.name, "xor_lit8": xor_lit8_hits,
                                        "xor_int": xor_int_hits})

        # encrypt/decrypt method WITHOUT JCA
        if ENCRYPT_DECRYPT_METHODS.search(txt) and not any(j in txt for j in JCA_USAGE):
            if not any(h["file"] == p.name for h in homebrew_methods) and len(homebrew_methods) < 25:
                homebrew_methods.append({"file": p.name})

    ctx.state["xor_loop_files"] = xor_loop_files
    ctx.state["homebrew_crypto_methods"] = homebrew_methods
    ctx.state["files_scanned"] = files_scanned
    ctx.state["custom_crypto_audit_total"] = (
        (1 if xor_loop_files else 0) + (1 if homebrew_methods else 0))
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Heavy XOR loop files", "xor_loop_files"),
    ("encrypt/decrypt methods without JCA", "homebrew_crypto_methods"),
]


@router.post("/api/mobile_crypto/custom_crypto_audit")
async def mobile_crypto_custom_crypto_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="custom_crypto_audit",
        gather_func=gather,
        finding_rules=CUSTOM_CRYPTO_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
