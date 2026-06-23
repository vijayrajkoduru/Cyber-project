"""dynamic_code_loading_audit - detect DexClassLoader / dlopen / NSBundle
loading of remote .dex/.so/.dylib at runtime. Usually how mobile malware
stages second-stage payloads. MSTG-CODE-9 / OWASP M3."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.dynamic_code_loading_audit_findings import DYNAMIC_CODE_LOADING_AUDIT_FINDING_RULES

router = APIRouter()
# DexClassLoader / PathClassLoader loading external dex is genuinely dynamic.
ANDROID_DEX_RE = re.compile(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader")
# Native loaders. NOTE: System.loadLibrary("name") of a *bundled* lib is the
# normal, safe way every NDK app loads its own .so and is NOT dynamic code
# loading -> excluded. We flag System.load()/Runtime.load (absolute path) and
# dlopen, which can load from arbitrary/writable paths.
ANDROID_DLOPEN_RE = re.compile(r"System\.load\(|Runtime\.load\b|\bdlopen\b")
SYSTEM_LOADLIBRARY_RE = re.compile(r"System\.loadLibrary\(|loadLibrary\s*\(")
IOS_DYLD_RE = re.compile(r"\bdlopen\b|NSBundle\.bundleWith[A-Z]|dyld_dynamic_linker")
REMOTE_URL_RE = re.compile(r"https?://[^\"'\s)]+\.(dex|jar|so|dylib|js|json)\b", re.IGNORECASE)
# Non-system / writable load paths: loading from these is the real risk signal.
WRITABLE_PATH_RE = re.compile(
    r"getFilesDir|getCacheDir|getExternalFilesDir|getExternalStorageDirectory|"
    r"/data/data/|/data/local/tmp|/sdcard/|getCodeCacheDir|getDir\s*\(|"
    r"download|/data/user/")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["dynamic_code_loading_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["dynamic_code_loading_audit_error"] = str(e); return
    dex_callers, dlopen_callers, ios_callers = [], [], []
    system_loadlibrary_only = []   # benign System.loadLibrary of bundled .so
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
        # System.load / Runtime.load / dlopen: only a risk signal when paired
        # with a writable/non-system path or remote URL. Otherwise it's loading
        # a bundled lib by name -> route to the benign bucket.
        has_native_load = bool(ANDROID_DLOPEN_RE.search(txt))
        has_writable = bool(WRITABLE_PATH_RE.search(txt))
        has_remote_here = bool(REMOTE_URL_RE.search(txt))
        if has_native_load:
            if has_writable or has_remote_here:
                if len(dlopen_callers) < 20:
                    dlopen_callers.append(p.name)
            elif len(system_loadlibrary_only) < 20:
                system_loadlibrary_only.append(p.name)
        elif SYSTEM_LOADLIBRARY_RE.search(txt) and len(system_loadlibrary_only) < 20:
            # Pure System.loadLibrary("bundled") — normal NDK pattern, benign.
            system_loadlibrary_only.append(p.name)
        if IOS_DYLD_RE.search(txt):
            # iOS dlopen of a system framework path is benign; require writable
            # or remote context to count as dynamic loading.
            if (has_writable or has_remote_here) and len(ios_callers) < 20:
                ios_callers.append(p.name)
        for m in REMOTE_URL_RE.finditer(txt):
            if len(remote_urls) < 15 and m.group(0) not in remote_urls:
                remote_urls.append(m.group(0))
    findings_total = 0
    if remote_urls and (dex_callers or dlopen_callers or ios_callers):
        findings_total += 1   # high — remote payload loading
    elif dex_callers or dlopen_callers or ios_callers:
        findings_total += 1   # medium — internal dynamic loading from non-system path
    ctx.state["dex_callers"] = dex_callers
    ctx.state["dlopen_callers"] = dlopen_callers
    ctx.state["ios_callers"] = ios_callers
    ctx.state["system_loadlibrary_only"] = system_loadlibrary_only
    ctx.state["remote_payload_urls"] = remote_urls
    ctx.state["files_scanned"] = files_scanned
    ctx.state["dynamic_code_loading_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("DexClassLoader callers", "dex_callers"),
                ("dlopen / System.load from writable path", "dlopen_callers"),
                ("iOS dyld callers", "ios_callers"),
                ("System.loadLibrary bundled (benign)", "system_loadlibrary_only"),
                ("Remote payload URLs", "remote_payload_urls")]


@router.post("/api/mobile_runtime/dynamic_code_loading_audit")
async def mobile_runtime_dynamic_code_loading_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="dynamic_code_loading_audit",
        gather_func=gather, finding_rules=DYNAMIC_CODE_LOADING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
