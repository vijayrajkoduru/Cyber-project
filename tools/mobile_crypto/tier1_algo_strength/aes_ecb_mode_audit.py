"""aes_ecb_mode_audit (§4 #47) — detect AES used in ECB mode, which leaks
plaintext patterns. The classic ECB-penguin bug. Should be CBC, CTR, or
preferably GCM (authenticated encryption)."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.aes_ecb_mode_audit_findings import AES_ECB_MODE_AUDIT_FINDING_RULES

router = APIRouter()

# Cipher.getInstance("AES") defaults to AES/ECB/PKCS5Padding on Android
ECB_PATTERNS = [
    re.compile(r'getInstance\("AES"\)'),                  # bare "AES" = ECB
    re.compile(r'getInstance\("AES/ECB[^"]*"'),
    re.compile(r'getInstance\("DES/ECB[^"]*"'),
    re.compile(r'getInstance\("Blowfish/ECB[^"]*"'),
    re.compile(r'getInstance\("AES/CBC/NoPadding"'),       # CBC+NoPad allows padding-oracle
]
GCM_PATTERN = re.compile(r'getInstance\("AES/GCM/NoPadding"\)')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["aes_ecb_mode_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["aes_ecb_mode_audit_error"] = str(e)
        return

    ecb_files = []
    gcm_files = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for pat in ECB_PATTERNS:
            if pat.search(txt):
                if p.name not in ecb_files and len(ecb_files) < 30:
                    ecb_files.append(p.name)
                break
        if GCM_PATTERN.search(txt):
            if p.name not in gcm_files and len(gcm_files) < 30:
                gcm_files.append(p.name)

    ctx.state["ecb_files"] = ecb_files
    ctx.state["gcm_files"] = gcm_files
    ctx.state["files_scanned"] = files_scanned
    ctx.state["aes_ecb_mode_audit_total"] = len(ecb_files)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("AES/ECB caller files", "ecb_files"),
    ("AES/GCM (good) caller files", "gcm_files"),
]


@router.post("/api/mobile_crypto/aes_ecb_mode_audit")
async def mobile_crypto_aes_ecb_mode_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="aes_ecb_mode_audit",
        gather_func=gather,
        finding_rules=AES_ECB_MODE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
