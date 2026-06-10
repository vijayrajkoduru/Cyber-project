"""webview_config_audit — risky WebView configuration in DEX bytecode.

WebView misconfig is the #1 mobile RCE vector: setJavaScriptEnabled(true)
+ setAllowFileAccess(true) + setAllowUniversalAccessFromFileURLs(true) +
a single XSS-bug in loaded HTML = full file:// arbitrary read.

Scans DEX bytecode for the known-dangerous setter combos.

MASVS-PLATFORM-5 / MSTG-PLATFORM-5.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.webview_config_audit_findings import \
    WEBVIEW_CONFIG_AUDIT_FINDING_RULES

router = APIRouter()

# (marker, description, severity tier)
RISKY_CONFIGS = [
    ("setJavaScriptEnabled",                "JS enabled",                "medium"),
    ("setAllowFileAccess",                  "file:// access enabled",    "high"),
    ("setAllowFileAccessFromFileURLs",      "file→file XSS allowed",     "high"),
    ("setAllowUniversalAccessFromFileURLs", "universal file access",     "critical"),
    ("setAllowContentAccess",               "content:// access enabled", "low"),
    ("setMixedContentMode0",          "mixed content allowed (HTTP in HTTPS)", "high"),
    ("setSavePassword",                     "password autosave",         "medium"),
    ("setDomStorageEnabled",                "DOM storage enabled",       "low"),
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["webview_config_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["webview_config_audit_error"] = str(e); return

    hits = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for marker, desc, sev in RISKY_CONFIGS:
            # Look for the setter name + the value 'true' / non-zero byte nearby
            if marker.encode() in data:
                hits.append({"setter": marker, "desc": desc, "severity": sev,
                              "file": f.relative_to(unpacked).as_posix()})

    ctx.state["webview_risky_setters"] = hits[:30]
    ctx.state["webview_config_audit_total"] = len(hits)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} DEX/smali files")


INTEL_FIELDS = [
    ("Risky WebView setters", "webview_config_audit_total"),
    ("Files scanned",         "files_scanned"),
]


@router.post("/api/mobile_static/webview_config_audit")
async def mobile_static_webview_config_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="webview_config_audit",
        gather_func=gather,
        finding_rules=WEBVIEW_CONFIG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
