"""iv_nonce_reuse_audit - hardcoded / reused IV for AES-CBC/CTR/GCM.

Catches: byte[] IV = new byte[16] (zero IV), hex IV literal in source,
IvParameterSpec(\"<literal>\") usage, GCMParameterSpec re-use. Critical
crypto bug - one reused GCM nonce loses both confidentiality and
authenticity. MSTG-CRYPTO-3."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.iv_nonce_reuse_audit_findings import IV_NONCE_REUSE_AUDIT_FINDING_RULES

router = APIRouter()
IV_LITERAL_RE = re.compile(r'IvParameterSpec\s*\(\s*"([^"]+)"|IvParameterSpec\s*\(\s*new\s+byte\[\s*\d+\s*\]')
GCM_LITERAL_RE = re.compile(r'GCMParameterSpec\s*\(\s*\d+\s*,\s*"([^"]+)"|GCMParameterSpec\s*\(\s*\d+\s*,\s*new\s+byte\[')
IOS_IV_RE = re.compile(r'CCCryptorCreate\s*\([^,]+,\s*0,|"00000000000000000000000000000000"')
ZERO_BYTE_RE = re.compile(r'new\s+byte\s*\[\s*(8|12|16)\s*\]')
SECURE_RANDOM_RE = re.compile(r'SecureRandom\(\)|nextBytes')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["iv_nonce_reuse_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["iv_nonce_reuse_audit_error"] = str(e); return
    literal_ivs, zero_ivs = [], []
    secure_random_co = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if IV_LITERAL_RE.search(txt) or GCM_LITERAL_RE.search(txt) or IOS_IV_RE.search(txt):
            if len(literal_ivs) < 20:
                literal_ivs.append(p.name)
        if ZERO_BYTE_RE.search(txt) and ("IvParameterSpec" in txt or "GCMParameterSpec" in txt or "Cipher" in txt):
            if len(zero_ivs) < 20:
                zero_ivs.append(p.name)
        if SECURE_RANDOM_RE.search(txt) and ("Iv" in txt or "Cipher" in txt):
            secure_random_co += 1
    findings_total = 0
    if literal_ivs or zero_ivs:
        findings_total += 1
    ctx.state["literal_iv_files"] = literal_ivs
    ctx.state["zero_iv_files"] = zero_ivs
    ctx.state["secure_random_co_usage"] = secure_random_co
    ctx.state["files_scanned"] = files_scanned
    ctx.state["iv_nonce_reuse_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Literal IV / nonce", "literal_iv_files"),
                ("Zero byte[] IV near Cipher", "zero_iv_files"),
                ("SecureRandom + Cipher co-located", "secure_random_co_usage")]


@router.post("/api/mobile_crypto/iv_nonce_reuse_audit")
async def mobile_crypto_iv_nonce_reuse_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="iv_nonce_reuse_audit",
        gather_func=gather, finding_rules=IV_NONCE_REUSE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
