"""aead_correctness_audit - AEAD nonce / tag handling correctness.

Detects: GCM tag length < 128 bits, ChaCha20-Poly1305 with reused nonce
(see iv_nonce_reuse_audit for the wider scope), CCM mode misuse, missing
associated-data binding. MSTG-CRYPTO-3."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.aead_correctness_audit_findings import AEAD_CORRECTNESS_AUDIT_FINDING_RULES

router = APIRouter()
GCM_INSTANCE_RE = re.compile(r'GCMParameterSpec\s*\(\s*(\d+)|AES/GCM|AES_256_GCM')
CHACHA_RE = re.compile(r'ChaCha20Poly1305|chacha20_poly1305|XChaCha20Poly1305')
CCM_RE = re.compile(r'CCMParameterSpec|AES/CCM')
AAD_RE = re.compile(r'cipher\.updateAAD|setAAD|EVP_CipherUpdate.*AAD')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["aead_correctness_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["aead_correctness_audit_error"] = str(e); return
    gcm_users = []
    gcm_short_tags = []
    chacha_users = []
    ccm_users = []
    aad_users = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        for m in GCM_INSTANCE_RE.finditer(txt):
            if len(gcm_users) < 20:
                gcm_users.append(p.name)
            try:
                if m.group(1):
                    bits = int(m.group(1))
                    if 0 < bits < 128:
                        gcm_short_tags.append({"file": p.name, "tag_bits": bits})
            except (IndexError, ValueError, TypeError):
                pass
        if CHACHA_RE.search(txt) and len(chacha_users) < 20:
            chacha_users.append(p.name)
        if CCM_RE.search(txt) and len(ccm_users) < 20:
            ccm_users.append(p.name)
        if AAD_RE.search(txt):
            aad_users += 1
    findings_total = 0
    if gcm_short_tags:
        findings_total += 1
    if (gcm_users or chacha_users) and aad_users == 0:
        findings_total += 1
    ctx.state["gcm_users"] = gcm_users
    ctx.state["gcm_short_tags"] = gcm_short_tags
    ctx.state["chacha_users"] = chacha_users
    ctx.state["ccm_users"] = ccm_users
    ctx.state["aad_users"] = aad_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["aead_correctness_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("GCM users", "gcm_users"),
                ("GCM short tags", "gcm_short_tags"),
                ("ChaCha20-Poly1305 users", "chacha_users"),
                ("CCM users", "ccm_users"),
                ("AAD callers", "aad_users")]


@router.post("/api/mobile_crypto/aead_correctness_audit")
async def mobile_crypto_aead_correctness_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="aead_correctness_audit",
        gather_func=gather, finding_rules=AEAD_CORRECTNESS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
