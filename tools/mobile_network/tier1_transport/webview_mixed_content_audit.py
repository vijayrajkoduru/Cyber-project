"""webview_mixed_content_audit - Android setMixedContentMode loose policy.
MIXED_CONTENT_ALWAYS_ALLOW (0) lets HTTPS pages load HTTP subresources.
Default since API 21 should be MIXED_CONTENT_NEVER_ALLOW (1). MSTG-PLATFORM-2."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.webview_mixed_content_audit_findings import WEBVIEW_MIXED_CONTENT_AUDIT_FINDING_RULES

router = APIRouter()
MIXED_ALWAYS_RE = re.compile(r'setMixedContentMode\s*\(\s*(?:0|MIXED_CONTENT_ALWAYS_ALLOW)')
MIXED_NEVER_RE = re.compile(r'setMixedContentMode\s*\(\s*(?:1|MIXED_CONTENT_NEVER_ALLOW)')
MIXED_COMPAT_RE = re.compile(r'setMixedContentMode\s*\(\s*(?:2|MIXED_CONTENT_COMPATIBILITY_MODE)')
WEBVIEW_RE = re.compile(r'WebView\s*\(|getSettings\(\)')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["webview_mixed_content_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["webview_mixed_content_audit_error"] = str(e); return
    always_allow = []
    never_allow = 0
    compat = 0
    webview_users = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if MIXED_ALWAYS_RE.search(txt) and len(always_allow) < 20:
            always_allow.append(p.name)
        if MIXED_NEVER_RE.search(txt): never_allow += 1
        if MIXED_COMPAT_RE.search(txt): compat += 1
        if WEBVIEW_RE.search(txt) and len(webview_users) < 20:
            webview_users.append(p.name)
    findings_total = 1 if always_allow else 0
    ctx.state["always_allow_callers"] = always_allow
    ctx.state["never_allow_callers"] = never_allow
    ctx.state["compatibility_callers"] = compat
    ctx.state["webview_users"] = webview_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["webview_mixed_content_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("MIXED_CONTENT_ALWAYS_ALLOW", "always_allow_callers"),
                ("MIXED_CONTENT_NEVER_ALLOW", "never_allow_callers"),
                ("COMPATIBILITY mode", "compatibility_callers"),
                ("WebView users", "webview_users")]


@router.post("/api/mobile_network/webview_mixed_content_audit")
async def mobile_network_webview_mixed_content_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="webview_mixed_content_audit",
        gather_func=gather, finding_rules=WEBVIEW_MIXED_CONTENT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
