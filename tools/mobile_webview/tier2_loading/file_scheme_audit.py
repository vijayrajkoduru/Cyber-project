"""file_scheme_audit - WebView file:// + allowFileAccess + UXSS. MASVS-PLATFORM-2."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.file_scheme_audit_findings import FILE_SCHEME_AUDIT_FINDING_RULES

router = APIRouter()
ALLOW_FILE_RE = re.compile(r'setAllowFileAccess\s*\(\s*true\s*\)')
ALLOW_FROM_FILE_RE = re.compile(r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)')
FILE_URL_RE = re.compile(r'"file://')
WEBVIEW_RE = re.compile(r'WebView|WebSettings|getSettings\(\)')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["file_scheme_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["file_scheme_audit_error"] = str(e); return
    allow_file, allow_from_file, file_urls = [], [], []
    webview_users = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if ALLOW_FILE_RE.search(txt) and len(allow_file) < 20: allow_file.append(p.name)
        if ALLOW_FROM_FILE_RE.search(txt) and len(allow_from_file) < 20: allow_from_file.append(p.name)
        if FILE_URL_RE.search(txt) and len(file_urls) < 20: file_urls.append(p.name)
        if WEBVIEW_RE.search(txt): webview_users += 1
    findings_total = 0
    if allow_from_file: findings_total += 1
    if allow_file: findings_total += 1
    ctx.state["allow_file_access"] = allow_file
    ctx.state["allow_from_file_urls"] = allow_from_file
    ctx.state["file_url_loaders"] = file_urls
    ctx.state["webview_users"] = webview_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["file_scheme_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("setAllowFileAccess(true)", "allow_file_access"),
                ("setAllowFileAccessFromFileURLs(true)", "allow_from_file_urls"),
                ("file:// loaders", "file_url_loaders"),
                ("WebView users", "webview_users")]


@router.post("/api/mobile_webview/file_scheme_audit")
async def mobile_webview_file_scheme_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="file_scheme_audit",
        gather_func=gather, finding_rules=FILE_SCHEME_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
