"""rsa_key_size_audit - RSA modulus size + ECDSA curve choice.
Floors (NIST/OWASP 2023): RSA >= 2048, ECDSA secp256r1+. MSTG-CRYPTO-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.rsa_key_size_audit_findings import RSA_KEY_SIZE_AUDIT_FINDING_RULES

router = APIRouter()
RSA_INIT_RE = re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*"RSA"|RSA_generate_key|SecKeyGeneratePair')
RSA_SIZE_RE = re.compile(r'initialize\s*\(\s*(\d+)\s*\)|kSecAttrKeySizeInBits.*?(\d+)|RSA_generate_key\s*\(\s*(\d+)')
EC_RE = re.compile(r'EC\s*KeyPairGenerator|ECGenParameterSpec\s*\(\s*"([^"]+)"|secp(\d+)r1|prime256v1|secp521r1')
WEAK_CURVE_RE = re.compile(r'secp160r1|secp192r1|secp224r1|secp192k1')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["rsa_key_size_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["rsa_key_size_audit_error"] = str(e); return
    rsa_callers = []
    rsa_too_small = []
    ec_callers = []
    weak_curves = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if RSA_INIT_RE.search(txt):
            if len(rsa_callers) < 20:
                rsa_callers.append(p.name)
            for m in RSA_SIZE_RE.finditer(txt):
                n = m.group(1) or m.group(2) or m.group(3)
                try:
                    sz = int(n)
                    if 0 < sz < 2048:
                        rsa_too_small.append({"file": p.name, "bits": sz})
                except (ValueError, TypeError): pass
        if EC_RE.search(txt) and len(ec_callers) < 20:
            ec_callers.append(p.name)
        if WEAK_CURVE_RE.search(txt) and len(weak_curves) < 20:
            weak_curves.append(p.name)
    findings_total = 0
    if rsa_too_small:
        findings_total += 1
    if weak_curves:
        findings_total += 1
    ctx.state["rsa_callers"] = rsa_callers
    ctx.state["rsa_too_small"] = rsa_too_small[:20]
    ctx.state["ec_callers"] = ec_callers
    ctx.state["weak_curve_users"] = weak_curves
    ctx.state["files_scanned"] = files_scanned
    ctx.state["rsa_key_size_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("RSA callers", "rsa_callers"),
                ("RSA < 2048", "rsa_too_small"),
                ("ECDSA callers", "ec_callers"),
                ("Weak EC curves", "weak_curve_users")]


@router.post("/api/mobile_crypto/rsa_key_size_audit")
async def mobile_crypto_rsa_key_size_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="rsa_key_size_audit",
        gather_func=gather, finding_rules=RSA_KEY_SIZE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
