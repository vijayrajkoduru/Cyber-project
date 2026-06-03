"""webview_ssl_error_audit - Android WebViewClient onReceivedSslError proceed.

onReceivedSslError -> handler.proceed() is the most common WebView TLS-
bypass: app ships its own browser and silently accepts any cert. MSTG-PLATFORM-2,
MSTG-NETWORK-3."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.webview_ssl_error_audit_findings import WEBVIEW_SSL_ERROR_AUDIT_FINDING_RULES

router = APIRouter()
SSL_HANDLER_RE = re.compile(r'onReceivedSslError[^{]*\{[^}]*proceed\s*\(', re.DOTALL)
SSL_CANCEL_RE = re.compile(r'onReceivedSslError[^{]*\{[^}]*cancel\s*\(', re.DOTALL)
WEBVIEW_RE = re.compile(r'WebViewClient\s*\(|WKWebView|UIWebView')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["webview_ssl_error_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["webview_ssl_error_audit_error"] = str(e); return
    proceed_overrides = []
    cancel_overrides = 0
    webview_users = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if SSL_HANDLER_RE.search(txt) and len(proceed_overrides) < 20:
            proceed_overrides.append(p.name)
        if SSL_CANCEL_RE.search(txt): cancel_overrides += 1
        if WEBVIEW_RE.search(txt) and len(webview_users) < 20:
            webview_users.append(p.name)
    findings_total = 1 if proceed_overrides else 0
    ctx.state["proceed_overrides"] = proceed_overrides
    ctx.state["cancel_overrides"] = cancel_overrides
    ctx.state["webview_users"] = webview_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["webview_ssl_error_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("handler.proceed() overrides", "proceed_overrides"),
                ("handler.cancel() overrides", "cancel_overrides"),
                ("WebView users", "webview_users")]


@router.post("/api/mobile_network/webview_ssl_error_audit")
async def mobile_network_webview_ssl_error_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="webview_ssl_error_audit",
        gather_func=gather, finding_rules=WEBVIEW_SSL_ERROR_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
