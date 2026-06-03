"""override_url_loading_audit - WebViewClient shouldOverrideUrlLoading default true."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.override_url_loading_audit_findings import OVERRIDE_URL_LOADING_AUDIT_FINDING_RULES

router = APIRouter()
OVERRIDE_TRUE_RE = re.compile(r'shouldOverrideUrlLoading[^{]*\{[^}]*return\s+true', re.DOTALL)
HOST_ALLOWLIST_RE = re.compile(r'\.equals\(|\.endsWith\(|host\.contains\(')
WEBVIEW_RE = re.compile(r'WebView|WebViewClient')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["override_url_loading_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["override_url_loading_audit_error"] = str(e); return
    blind_overrides, allowlisted, webview_users = [], 0, 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if WEBVIEW_RE.search(txt): webview_users += 1
        if OVERRIDE_TRUE_RE.search(txt):
            if HOST_ALLOWLIST_RE.search(txt): allowlisted += 1
            elif len(blind_overrides) < 20: blind_overrides.append(p.name)
    findings_total = 1 if blind_overrides else 0
    ctx.state["blind_overrides"] = blind_overrides
    ctx.state["allowlisted_overrides"] = allowlisted
    ctx.state["webview_users"] = webview_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["override_url_loading_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Blind override returns true", "blind_overrides"),
                ("Allowlisted overrides", "allowlisted_overrides"),
                ("WebView users", "webview_users")]


@router.post("/api/mobile_webview/override_url_loading_audit")
async def mobile_webview_override_url_loading_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="override_url_loading_audit",
        gather_func=gather, finding_rules=OVERRIDE_URL_LOADING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
