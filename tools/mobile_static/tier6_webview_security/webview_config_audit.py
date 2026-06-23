"""webview_config_audit — risky WebView configuration in DEX bytecode.

WebView misconfig is the #1 mobile RCE vector: setJavaScriptEnabled(true)
+ setAllowFileAccess(true) + setAllowUniversalAccessFromFileURLs(true) +
a single XSS-bug in loaded HTML = full file:// arbitrary read.

Scans DEX bytecode for the known-dangerous setter combos.

MASVS-PLATFORM-5 / MSTG-PLATFORM-5.
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.webview_config_audit_findings import \
    WEBVIEW_CONFIG_AUDIT_FINDING_RULES
from tools._payloads.mobile._fp_gates import is_app_code_path

router = APIRouter()

# (marker, description, severity tier)
RISKY_CONFIGS = [
    ("setJavaScriptEnabled",                "JS enabled",                "medium"),
    ("setAllowFileAccess",                  "file:// access enabled",    "high"),
    ("setAllowFileAccessFromFileURLs",      "file→file XSS allowed",     "high"),
    ("setAllowUniversalAccessFromFileURLs", "universal file access",     "critical"),
    ("setAllowContentAccess",               "content:// access enabled", "low"),
    ("setMixedContentMode",                 "mixed content mode set (verify not MIXED_CONTENT_ALWAYS_ALLOW)", "high"),
    ("setSavePassword",                     "password autosave",         "high"),
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

    # Boolean-enable setters: a hit only matters when the value is TRUE. In smali
    # that's a const 0x1 moved into the arg register just before the invoke.
    bool_setters = {"setAllowFileAccess", "setAllowFileAccessFromFileURLs",
                    "setAllowUniversalAccessFromFileURLs", "setAllowContentAccess",
                    "setJavaScriptEnabled", "setSavePassword", "setDomStorageEnabled"}

    def _enabled_true(text, marker):
        # smali: a `const/4 vX, 0x1` (true) loaded within a few lines before the
        # setX(Z)V invoke. If we only ever see `0x0` (false) near the setter, the
        # config is safe and should not be flagged.
        pat = re.compile(r"const(?:/4|/16)?\s+v\d+,\s*0x1\b(?:[^\n]*\n){0,4}?[^\n]*"
                         + re.escape(marker), re.MULTILINE)
        return bool(pat.search(text))

    hits = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali") and "classes" not in f.name: continue
        is_smali = f.suffix == ".smali"
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        try:
            rel = f.relative_to(unpacked).as_posix()
        except ValueError:
            rel = f.name
        # "presence != usage": .dex is multidex (can't attribute to app vs SDK);
        # per-class .smali can. Only app-code smali is graded; .dex/SDK -> context.
        app_code = is_smali and is_app_code_path(rel)
        text = data.decode("latin-1", errors="ignore") if is_smali else ""
        for marker, desc, sev in RISKY_CONFIGS:
            if marker.encode() not in data:
                continue
            # For boolean setters in smali, require the value to actually be TRUE.
            if is_smali and marker in bool_setters:
                confirmed = _enabled_true(text, marker)
            else:
                confirmed = not is_smali  # dex hit: unattributable -> not confirmed-true
            hits.append({"setter": marker, "desc": desc, "severity": sev,
                          "file": rel,
                          "app_code": bool(app_code),
                          "confirmed": bool(confirmed)})

    ctx.state["webview_risky_setters"] = hits[:30]
    # Only app-code, value-confirmed setters drive the graded total.
    graded = [h for h in hits if h["app_code"] and h["confirmed"]]
    ctx.state["webview_graded_setters"] = graded[:30]
    ctx.state["webview_config_audit_total"] = len(graded)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} DEX/smali files")


INTEL_FIELDS = [
    ("Risky WebView setters (graded)", "webview_config_audit_total"),
    ("All risky setter references",    "webview_risky_setters"),
    ("Files scanned",                  "files_scanned"),
]


@router.post("/api/mobile_static/webview_config_audit")
async def mobile_static_webview_config_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="webview_config_audit",
        gather_func=gather,
        finding_rules=WEBVIEW_CONFIG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
