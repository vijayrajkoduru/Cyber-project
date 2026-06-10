"""deep_link_hijack_audit - custom-scheme deep link + app-link hijack.

Custom <intent-filter android:scheme="myapp"> without app-link verification
lets a competing app register the same scheme. App-link (autoVerify=true)
requires .well-known/assetlinks.json proof. MASVS-PLATFORM-3, MSTG-PLATFORM-3."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.deep_link_hijack_audit_findings import DEEP_LINK_HIJACK_AUDIT_FINDING_RULES

router = APIRouter()
INTENT_FILTER_RE = re.compile(r'<intent-filter[^>]*>(.*?)</intent-filter>', re.DOTALL | re.IGNORECASE)
SCHEME_RE = re.compile(r'android:scheme="([^"]+)"')
HOST_RE = re.compile(r'android:host="([^"]+)"')
AUTOVERIFY_RE = re.compile(r'android:autoVerify="true"')
HTTP_SCHEMES = {"http", "https"}
SCAN_MAX_FILES = 1000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["deep_link_hijack_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["deep_link_hijack_audit_error"] = str(e); return
    custom_scheme_unverified = []
    http_link_unverified = []
    verified = 0
    files_scanned = 0
    for p in unpacked.rglob("*.xml"):
        if files_scanned >= SCAN_MAX_FILES: break
        if "AndroidManifest" not in p.name and "manifest" not in p.name.lower(): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        for m in INTENT_FILTER_RE.finditer(txt):
            block = m.group(0)
            for sm in SCHEME_RE.finditer(block):
                sch = sm.group(1).lower()
                is_verified = bool(AUTOVERIFY_RE.search(block))
                host_m = HOST_RE.search(block)
                host = host_m.group(1) if host_m else "(no host)"
                entry = {"scheme": sch, "host": host[:60]}
                if sch in HTTP_SCHEMES:
                    if is_verified: verified += 1
                    else: http_link_unverified.append(entry)
                else:
                    if not is_verified:
                        custom_scheme_unverified.append(entry)
                if len(custom_scheme_unverified) + len(http_link_unverified) >= 25: break
    findings_total = 0
    if http_link_unverified: findings_total += 1
    if custom_scheme_unverified: findings_total += 1
    ctx.state["custom_scheme_unverified"] = custom_scheme_unverified
    ctx.state["http_link_unverified"] = http_link_unverified
    ctx.state["verified_app_links"] = verified
    ctx.state["files_scanned"] = files_scanned
    ctx.state["deep_link_hijack_audit_total"] = findings_total
    ctx.source(f"{files_scanned} manifests")


INTEL_FIELDS = [("Custom scheme (unverified)", "custom_scheme_unverified"),
                ("HTTP/S link (unverified)", "http_link_unverified"),
                ("Verified app-links", "verified_app_links")]


@router.post("/api/mobile_ipc/deep_link_hijack_audit")
async def mobile_ipc_deep_link_hijack_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="deep_link_hijack_audit",
        gather_func=gather, finding_rules=DEEP_LINK_HIJACK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
