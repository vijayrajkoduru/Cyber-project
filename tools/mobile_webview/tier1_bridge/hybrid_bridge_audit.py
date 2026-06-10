"""hybrid_bridge_audit - Cordova / Capacitor / Ionic / React Native bridge audit.
Dangerous-by-default plugin exposure + custom plugin without allowlist."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.hybrid_bridge_audit_findings import HYBRID_BRIDGE_AUDIT_FINDING_RULES

router = APIRouter()
CORDOVA_RE = re.compile(r'cordova-plugin-|CordovaPlugin|window\.cordova')
CAPACITOR_RE = re.compile(r'@capacitor/|CapacitorPlugin|window\.Capacitor')
IONIC_RE = re.compile(r'@ionic/|Ionic\.WebView')
REACT_NATIVE_RE = re.compile(r'react-native|ReactNative|NativeModules\.')
PLUGIN_FILE_ACCESS_RE = re.compile(r'cordova-plugin-file|cordova-plugin-file-transfer|cordova-plugin-camera|@capacitor/filesystem')
PLUGIN_ALLOWLIST_RE = re.compile(r'<allow-navigation|<allow-intent|allowedNavigation|server\.allowNavigation')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["hybrid_bridge_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["hybrid_bridge_audit_error"] = str(e); return
    fw = {"cordova": [], "capacitor": [], "ionic": [], "react_native": []}
    dangerous_plugins = []
    has_allowlist = False
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".js", ".json", ".smali", ".java", ".xml", ".plist"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if CORDOVA_RE.search(txt) and len(fw["cordova"]) < 10: fw["cordova"].append(p.name)
        if CAPACITOR_RE.search(txt) and len(fw["capacitor"]) < 10: fw["capacitor"].append(p.name)
        if IONIC_RE.search(txt) and len(fw["ionic"]) < 10: fw["ionic"].append(p.name)
        if REACT_NATIVE_RE.search(txt) and len(fw["react_native"]) < 10: fw["react_native"].append(p.name)
        if PLUGIN_FILE_ACCESS_RE.search(txt) and len(dangerous_plugins) < 20: dangerous_plugins.append(p.name)
        if PLUGIN_ALLOWLIST_RE.search(txt): has_allowlist = True
    detected_any = any(fw[k] for k in fw)
    findings_total = 1 if (detected_any and dangerous_plugins and not has_allowlist) else 0
    ctx.state["frameworks_detected"] = {k: len(v) for k, v in fw.items()}
    ctx.state["dangerous_plugins"] = dangerous_plugins
    ctx.state["navigation_allowlist_present"] = has_allowlist
    ctx.state["files_scanned"] = files_scanned
    ctx.state["hybrid_bridge_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Frameworks detected", "frameworks_detected"),
                ("Dangerous plugins (file/camera/transfer)", "dangerous_plugins"),
                ("Navigation allowlist present", "navigation_allowlist_present")]


@router.post("/api/mobile_webview/hybrid_bridge_audit")
async def mobile_webview_hybrid_bridge_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="hybrid_bridge_audit",
        gather_func=gather, finding_rules=HYBRID_BRIDGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
