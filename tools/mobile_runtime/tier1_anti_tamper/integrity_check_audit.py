"""integrity_check_audit - APK signature + code-integrity checks at runtime.

Android: PackageManager.getPackageInfo(GET_SIGNATURES) + SHA-256 of signing
         cert compared to a baked-in value. iOS: codeSignDynamicValidity
         or SecCodeCopySelf + SecCodeCheckValidity. MSTG-RESILIENCE-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.integrity_check_audit_findings import INTEGRITY_CHECK_AUDIT_FINDING_RULES

router = APIRouter()
ANDROID_SIG_RE = re.compile(r"GET_SIGNATURES|signingInfo|getPackageInfo\([^)]*PackageManager\$GET_SIGN")
ANDROID_BASELINE_RE = re.compile(r"SHA-?256|MessageDigest\.getInstance\(\"SHA-?256\"\)")
IOS_CODESIGN_RE = re.compile(r"SecCodeCopySelf|SecCodeCheckValidity|csops|csflags")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["integrity_check_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["integrity_check_audit_error"] = str(e); return
    android_sig_calls, android_sha_calls = [], []
    ios_codesign = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if ANDROID_SIG_RE.search(txt) and len(android_sig_calls) < 20:
            android_sig_calls.append(p.name)
        if ANDROID_BASELINE_RE.search(txt) and len(android_sha_calls) < 20:
            android_sha_calls.append(p.name)
        if IOS_CODESIGN_RE.search(txt) and len(ios_codesign) < 20:
            ios_codesign.append(p.name)
    findings_total = 0
    if not android_sig_calls and not ios_codesign:
        findings_total += 1
    ctx.state["android_sig_calls"] = android_sig_calls
    ctx.state["android_sha_calls"] = android_sha_calls
    ctx.state["ios_codesign"] = ios_codesign
    ctx.state["files_scanned"] = files_scanned
    ctx.state["integrity_check_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Android signature check", "android_sig_calls"),
                ("Android SHA-256 usage", "android_sha_calls"),
                ("iOS codesign check", "ios_codesign")]


@router.post("/api/mobile_runtime/integrity_check_audit")
async def mobile_runtime_integrity_check_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="integrity_check_audit",
        gather_func=gather, finding_rules=INTEGRITY_CHECK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
