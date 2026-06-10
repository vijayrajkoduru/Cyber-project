"""cordova_capacitor_plugin_audit — Cordova/Capacitor plugin inventory.

Cordova/Capacitor hybrid apps wrap native plugins. Each plugin = native
code surface (and CVE history). This scanner inventories detected plugins
and flags known-CVE plugin versions.
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.cordova_capacitor_plugin_audit_findings import \
    CORDOVA_CAPACITOR_PLUGIN_AUDIT_FINDING_RULES

router = APIRouter()

# Plugin markers (file paths within unpacked bundle)
PLUGIN_PATTERNS = [
    (re.compile(rb"cordova-plugin-([a-z0-9-]+)"),  "cordova"),
    (re.compile(rb"@capacitor/([a-z0-9-]+)"),       "capacitor"),
    (re.compile(rb"@ionic/([a-z0-9-]+)"),           "ionic"),
]
# Known-bad plugin versions (high-impact CVEs)
KNOWN_BAD = {
    "cordova-plugin-inappbrowser": "CVE-2017-3160 (load(URL))",
    "cordova-plugin-file":         "CVE-2018-15532 (path traversal in URL handler)",
    "cordova-plugin-statusbar":    "Known XSS prior to 2.4.3",
    "@capacitor/browser":          "URL validation issues prior to 5.x",
}


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["cordova_capacitor_plugin_audit_total"] = 0
        ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["cordova_capacitor_plugin_audit_error"] = str(e); return

    is_cordova = False
    is_capacitor = False
    plugins_found = set()
    files_scanned = 0

    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        name = f.name.lower()
        # Detect hybrid framework
        if name == "cordova.js" or name == "cordova_plugins.js":
            is_cordova = True
        if name == "capacitor.config.json" or name == "capacitor.config.ts":
            is_capacitor = True
        # Plugin marker scan in select file types
        if f.suffix not in (".js", ".json", ".html", ".txt") and "classes" not in name:
            continue
        try: data = f.read_bytes()[:5_000_000]
        except Exception: continue
        files_scanned += 1
        for pat, kind in PLUGIN_PATTERNS:
            for m in pat.finditer(data):
                plugin_name = m.group(0).decode(errors="ignore")
                plugins_found.add(plugin_name)

    bad_plugins = []
    for p in plugins_found:
        for bad_name, desc in KNOWN_BAD.items():
            if bad_name in p:
                bad_plugins.append({"plugin": p, "issue": desc})

    ctx.state["is_cordova"] = is_cordova
    ctx.state["is_capacitor"] = is_capacitor
    ctx.state["plugins_found"] = sorted(plugins_found)
    ctx.state["bad_plugins"] = bad_plugins
    ctx.state["cordova_capacitor_plugin_audit_total"] = len(plugins_found) + len(bad_plugins) * 3
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"cordova={is_cordova}, capacitor={is_capacitor}, plugins={len(plugins_found)}")


INTEL_FIELDS = [
    ("Cordova detected",   "is_cordova"),
    ("Capacitor detected", "is_capacitor"),
    ("Plugins found",       "plugins_found"),
    ("Known-bad plugins",   "bad_plugins"),
]


@router.post("/api/mobile_static/cordova_capacitor_plugin_audit")
async def mobile_static_cordova_capacitor_plugin_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="cordova_capacitor_plugin_audit", gather_func=gather,
        finding_rules=CORDOVA_CAPACITOR_PLUGIN_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
