"""webview_cache_audit — audit WebView cache/storage configuration.
Risky: setAppCacheEnabled(true), setDomStorageEnabled(true) without
clearCache(), setSaveFormData(true), setSavePassword(true) (legacy),
no setMixedContentMode policy."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.webview_cache_audit_findings import WEBVIEW_CACHE_AUDIT_FINDING_RULES

router = APIRouter()

WEBVIEW_RISK_MARKERS = {
    "setAppCacheEnabled": "AppCache enabled (deprecated, leaks via cache dir)",
    "setSaveFormData": "Form-data auto-save enabled (deprecated; leaks PII)",
    "setSavePassword": "Password auto-save enabled (deprecated; major leak)",
    "setAllowFileAccess": "file:// access enabled (UXSS risk)",
    "setAllowFileAccessFromFileURLs": "file:// CSP relaxed (universal XSS)",
    "setAllowUniversalAccessFromFileURLs": "universal access from file:// (UXSS)",
    "setMixedContentMode": "mixed-content set - verify mode is COMPAT or NEVER_ALLOW",
}
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["webview_cache_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["webview_cache_audit_error"] = str(e)
        return

    webview_users = []
    risk_hits = {}
    has_clear_cache = False
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        if "android/webkit/WebView" in txt or "WebView.loadUrl" in txt:
            if len(webview_users) < 20:
                webview_users.append(p.name)

        for marker, _desc in WEBVIEW_RISK_MARKERS.items():
            if marker in txt:
                risk_hits.setdefault(marker, [])
                if len(risk_hits[marker]) < 10:
                    risk_hits[marker].append(p.name)

        if "clearCache" in txt or "WebView->clearCache" in txt:
            has_clear_cache = True

    findings_total = len(risk_hits)
    if webview_users and not has_clear_cache:
        findings_total += 1

    ctx.state["webview_users"] = webview_users
    ctx.state["webview_risks"] = risk_hits
    ctx.state["webview_has_clear_cache"] = has_clear_cache
    ctx.state["files_scanned"] = files_scanned
    ctx.state["webview_cache_audit_total"] = findings_total
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("WebView callers", "webview_users"),
    ("Risky WebView API hits", "webview_risks"),
    ("clearCache() present", "webview_has_clear_cache"),
]


@router.post("/api/mobile_storage/webview_cache_audit")
async def mobile_storage_webview_cache_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="webview_cache_audit",
        gather_func=gather,
        finding_rules=WEBVIEW_CACHE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
