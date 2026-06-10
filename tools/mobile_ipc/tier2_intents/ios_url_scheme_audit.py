"""ios_url_scheme_audit - iOS CFBundleURLSchemes + Universal Link audit.

Custom URL schemes in Info.plist can be hijacked by another app installed
later (iOS calls the FIRST app to register). Universal Links via
apple-app-site-association are safer but need correct setup. MASVS-PLATFORM-3."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.ios_url_scheme_audit_findings import IOS_URL_SCHEME_AUDIT_FINDING_RULES

router = APIRouter()
URL_SCHEME_RE = re.compile(r'<key>CFBundleURLSchemes</key>\s*<array>(.*?)</array>', re.DOTALL)
SCHEME_VAL_RE = re.compile(r'<string>([^<]+)</string>')
QUERIES_SCHEMES_RE = re.compile(r'<key>LSApplicationQueriesSchemes</key>')
UNIVERSAL_LINK_RE = re.compile(r'com\.apple\.developer\.associated-domains|applinks:')
SCAN_MAX_FILES = 1000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ios_url_scheme_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["ios_url_scheme_audit_error"] = str(e); return
    is_ios = False
    declared_schemes = []
    queries_schemes_present = False
    universal_link_present = False
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".plist", ".entitlements"): continue
        is_ios = True
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        for m in URL_SCHEME_RE.finditer(txt):
            for sm in SCHEME_VAL_RE.finditer(m.group(1)):
                sch = sm.group(1).strip().lower()
                if sch and sch not in declared_schemes and len(declared_schemes) < 25:
                    declared_schemes.append(sch)
        if QUERIES_SCHEMES_RE.search(txt): queries_schemes_present = True
        if UNIVERSAL_LINK_RE.search(txt): universal_link_present = True
    findings_total = 0
    if is_ios and declared_schemes and not universal_link_present:
        findings_total += 1
    ctx.state["is_ios"] = is_ios
    ctx.state["declared_schemes"] = declared_schemes
    ctx.state["queries_schemes_present"] = queries_schemes_present
    ctx.state["universal_link_present"] = universal_link_present
    ctx.state["files_scanned"] = files_scanned
    ctx.state["ios_url_scheme_audit_total"] = findings_total
    ctx.source(f"{files_scanned} plist/entitlements")


INTEL_FIELDS = [("iOS detected", "is_ios"),
                ("CFBundleURLSchemes", "declared_schemes"),
                ("LSApplicationQueriesSchemes", "queries_schemes_present"),
                ("Universal Link configured", "universal_link_present")]


@router.post("/api/mobile_ipc/ios_url_scheme_audit")
async def mobile_ipc_ios_url_scheme_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="ios_url_scheme_audit",
        gather_func=gather, finding_rules=IOS_URL_SCHEME_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
