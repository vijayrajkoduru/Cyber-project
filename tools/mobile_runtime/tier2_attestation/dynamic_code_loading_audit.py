"""dynamic_code_loading_audit - detect DexClassLoader / dlopen / NSBundle
loading of remote .dex/.so/.dylib at runtime. Usually how mobile malware
stages second-stage payloads. MSTG-CODE-9 / OWASP M3."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.dynamic_code_loading_audit_findings import DYNAMIC_CODE_LOADING_AUDIT_FINDING_RULES

router = APIRouter()
ANDROID_DEX_RE = re.compile(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader")
ANDROID_DLOPEN_RE = re.compile(r"System\.load\(|System\.loadLibrary\(|Runtime\.load|dlopen")
IOS_DYLD_RE = re.compile(r"dlopen|NSBundle\.bundleWith[A-Z]|dyld_dynamic_linker")
REMOTE_URL_RE = re.compile(r"https?://[^\"'\s)]+\.(dex|jar|so|dylib|js|json)\b", re.IGNORECASE)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["dynamic_code_loading_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["dynamic_code_loading_audit_error"] = str(e); return
    dex_callers, dlopen_callers, ios_callers = [], [], []
    remote_urls = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if ANDROID_DEX_RE.search(txt) and len(dex_callers) < 20:
            dex_callers.append(p.name)
        if ANDROID_DLOPEN_RE.search(txt) and len(dlopen_callers) < 20:
            dlopen_callers.append(p.name)
        if IOS_DYLD_RE.search(txt) and len(ios_callers) < 20:
            ios_callers.append(p.name)
        for m in REMOTE_URL_RE.finditer(txt):
            if len(remote_urls) < 15 and m.group(0) not in remote_urls:
                remote_urls.append(m.group(0))
    findings_total = 0
    if remote_urls and (dex_callers or dlopen_callers or ios_callers):
        findings_total += 1   # high — remote payload loading
    elif dex_callers or dlopen_callers or ios_callers:
        findings_total += 1   # medium — internal dynamic loading
    ctx.state["dex_callers"] = dex_callers
    ctx.state["dlopen_callers"] = dlopen_callers
    ctx.state["ios_callers"] = ios_callers
    ctx.state["remote_payload_urls"] = remote_urls
    ctx.state["files_scanned"] = files_scanned
    ctx.state["dynamic_code_loading_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("DexClassLoader callers", "dex_callers"),
                ("dlopen / System.load callers", "dlopen_callers"),
                ("iOS dyld callers", "ios_callers"),
                ("Remote payload URLs", "remote_payload_urls")]


@router.post("/api/mobile_runtime/dynamic_code_loading_audit")
async def mobile_runtime_dynamic_code_loading_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="dynamic_code_loading_audit",
        gather_func=gather, finding_rules=DYNAMIC_CODE_LOADING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
