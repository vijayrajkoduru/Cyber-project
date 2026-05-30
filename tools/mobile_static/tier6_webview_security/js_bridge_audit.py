"""js_bridge_audit — @JavascriptInterface usage in DEX.

@JavascriptInterface methods are reachable from any JavaScript in the
WebView. Pre-API-17 they had a fatal RCE bug; on API-17+ they're safer
but still expose attack surface. Best practice: minimize, validate input,
prefer postMessage over JS interface.

MASVS-PLATFORM-5 / MSTG-PLATFORM-7.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.js_bridge_audit_findings import \
    JS_BRIDGE_AUDIT_FINDING_RULES

router = APIRouter()

# Smali-form vs dex-bytecode-form
MARKERS = [
    b"Landroid/webkit/JavascriptInterface;",  # smali class ref
    b"addJavascriptInterface",                 # method call
    b"@JavascriptInterface",                   # rarely in source-form
    b"javascriptinterface",
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["js_bridge_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["js_bridge_audit_error"] = str(e); return

    hits = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for marker in MARKERS:
            count = data.count(marker)
            if count:
                hits.append({"marker": marker.decode(errors="ignore"),
                              "count": count,
                              "file": f.relative_to(unpacked).as_posix()})

    ctx.state["js_bridge_hits"] = hits[:30]
    total = sum(h["count"] for h in hits)
    ctx.state["js_bridge_audit_total"] = total
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} DEX/smali files")


INTEL_FIELDS = [
    ("JS bridge marker occurrences", "js_bridge_audit_total"),
    ("Files scanned",                "files_scanned"),
]


@router.post("/api/mobile_static/js_bridge_audit")
async def mobile_static_js_bridge_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="js_bridge_audit",
        gather_func=gather,
        finding_rules=JS_BRIDGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
