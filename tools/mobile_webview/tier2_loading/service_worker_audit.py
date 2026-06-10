"""service_worker_audit - WebView Service Worker registration persistence."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.service_worker_audit_findings import SERVICE_WORKER_AUDIT_FINDING_RULES

router = APIRouter()
SW_REGISTER_RE = re.compile(r'navigator\.serviceWorker\.register|ServiceWorkerController')
SW_CACHE_RE = re.compile(r'caches\.open|CacheStorage|sw\.js')
WEBVIEW_SETTING_RE = re.compile(r'setServiceWorkerClient|ServiceWorkerController\.setServiceWorkerClient')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["service_worker_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["service_worker_audit_error"] = str(e); return
    sw_registers, sw_caches = [], []
    sw_managed = False
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".js", ".html", ".smali", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if SW_REGISTER_RE.search(txt) and len(sw_registers) < 20: sw_registers.append(p.name)
        if SW_CACHE_RE.search(txt) and len(sw_caches) < 20: sw_caches.append(p.name)
        if WEBVIEW_SETTING_RE.search(txt): sw_managed = True
    findings_total = 1 if (sw_registers and not sw_managed) else 0
    ctx.state["sw_register_calls"] = sw_registers
    ctx.state["sw_cache_calls"] = sw_caches
    ctx.state["sw_controller_set"] = sw_managed
    ctx.state["files_scanned"] = files_scanned
    ctx.state["service_worker_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("ServiceWorker register() calls", "sw_register_calls"),
                ("Cache API uses", "sw_cache_calls"),
                ("setServiceWorkerClient set", "sw_controller_set")]


@router.post("/api/mobile_webview/service_worker_audit")
async def mobile_webview_service_worker_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="service_worker_audit",
        gather_func=gather, finding_rules=SERVICE_WORKER_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
