"""external_url_loading_audit — find hardcoded HTTP(S) URLs WebView loads.

Scan DEX for WebView.loadUrl / loadDataWithBaseURL calls and adjacent
URL string constants. HTTP (not HTTPS) loads = MitM risk. Foreign-domain
HTTPS loads = third-party content rendered in app context.

MASVS-NETWORK-1 / MSTG-NETWORK-2.
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.external_url_loading_audit_findings import \
    EXTERNAL_URL_LOADING_AUDIT_FINDING_RULES

router = APIRouter()
URL_RE = re.compile(rb"\b(https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200})")
LOAD_MARKER_RE = re.compile(rb"loadUrl|loadDataWithBaseURL|webView\.load")


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["external_url_loading_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["external_url_loading_audit_error"] = str(e); return

    http_urls = set()
    https_urls = set()
    webview_using_files = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali", ".xml") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        is_webview_file = bool(LOAD_MARKER_RE.search(data))
        if is_webview_file:
            webview_using_files.append(f.relative_to(unpacked).as_posix())
        for m in URL_RE.finditer(data):
            url = m.group(1).decode(errors="ignore")
            # Skip cdn.example.com placeholder, schemas.android.com, etc.
            if any(skip in url for skip in (
                "schemas.android.com", "openssl.org", "ietf.org", "w3.org",
                "developer.android.com", "play.google.com", "apple.com",
                "example.com", "google-analytics.com")):
                continue
            if url.startswith("http://"):
                http_urls.add(url)
            elif url.startswith("https://"):
                https_urls.add(url)
            if len(http_urls) + len(https_urls) >= 200: break
        if len(http_urls) + len(https_urls) >= 200: break

    ctx.state["http_urls_in_bundle"] = sorted(http_urls)[:30]
    ctx.state["https_urls_in_bundle"] = sorted(https_urls)[:30]
    ctx.state["webview_using_files"] = webview_using_files[:10]
    ctx.state["http_url_count"] = len(http_urls)
    ctx.state["https_url_count"] = len(https_urls)
    ctx.state["external_url_loading_audit_total"] = len(http_urls)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned}, http={len(http_urls)}, https={len(https_urls)}")


INTEL_FIELDS = [
    ("HTTP URLs (insecure)", "http_url_count"),
    ("HTTPS URLs",           "https_url_count"),
    ("WebView files seen",   "webview_using_files"),
    ("Files scanned",        "files_scanned"),
]


@router.post("/api/mobile_static/external_url_loading_audit")
async def mobile_static_external_url_loading_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="external_url_loading_audit",
        gather_func=gather,
        finding_rules=EXTERNAL_URL_LOADING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
