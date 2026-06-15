"""addjavascriptinterface_audit - WebView.addJavascriptInterface RCE class.

Pre-API-17: any @JavascriptInterface method was Reflection-reachable -> RCE.
Even on modern Android, exposed methods that touch File/Runtime are risky.
MASVS-PLATFORM-2 / MSTG-PLATFORM-5."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.addjavascriptinterface_audit_findings import ADDJAVASCRIPTINTERFACE_AUDIT_FINDING_RULES
from tools._payloads.mobile._loader import load_json

router = APIRouter()
ADD_JS_RE = re.compile(r'addJavascriptInterface\s*\(')
JS_INTERFACE_ANN_RE = re.compile(r'@JavascriptInterface')
TARGET_SDK_RE = re.compile(r'targetSdkVersion="?(\d+)|android:targetSdkVersion="(\d+)"')
# Dangerous bridge-reachable methods sourced from the shared AI-curated mobile
# pool; inline list is the fallback. Joined into the same alternation regex.
_DANGEROUS_METHODS_FALLBACK = [r'Runtime\.getRuntime', 'ProcessBuilder',
                               'FileOutputStream', r'File\.createTempFile',
                               'getPackageManager']
_dangerous_methods = load_json("dangerous_webview_methods", fallback={}).get(
    "methods", _DANGEROUS_METHODS_FALLBACK) or _DANGEROUS_METHODS_FALLBACK
DANGEROUS_METHOD_RE = re.compile('|'.join(_dangerous_methods))
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["addjavascriptinterface_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["addjavascriptinterface_audit_error"] = str(e); return
    bridge_users, annotated_files = [], []
    danger_co = []
    target_sdk = None
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".xml"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if p.suffix == ".xml" and "manifest" in p.name.lower():
            tm = TARGET_SDK_RE.search(txt)
            if tm:
                try: target_sdk = int(tm.group(1) or tm.group(2))
                except (ValueError, TypeError): pass
            continue
        if ADD_JS_RE.search(txt):
            if len(bridge_users) < 20: bridge_users.append(p.name)
            if DANGEROUS_METHOD_RE.search(txt) and len(danger_co) < 20:
                danger_co.append(p.name)
        if JS_INTERFACE_ANN_RE.search(txt) and len(annotated_files) < 20:
            annotated_files.append(p.name)
    findings_total = 0
    if bridge_users and target_sdk and target_sdk < 17: findings_total += 1
    if danger_co: findings_total += 1
    if bridge_users and not annotated_files: findings_total += 1
    ctx.state["bridge_users"] = bridge_users
    ctx.state["annotated_files"] = annotated_files
    ctx.state["dangerous_method_co"] = danger_co
    ctx.state["target_sdk"] = target_sdk
    ctx.state["files_scanned"] = files_scanned
    ctx.state["addjavascriptinterface_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("addJavascriptInterface users", "bridge_users"),
                ("@JavascriptInterface annotated", "annotated_files"),
                ("Dangerous methods near bridge", "dangerous_method_co"),
                ("targetSdkVersion", "target_sdk")]


@router.post("/api/mobile_webview/addjavascriptinterface_audit")
async def mobile_webview_addjavascriptinterface_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="addjavascriptinterface_audit",
        gather_func=gather, finding_rules=ADDJAVASCRIPTINTERFACE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
