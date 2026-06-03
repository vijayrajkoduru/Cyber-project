"""method_swizzling_audit - iOS Objective-C runtime swizzling defense.

method_exchangeImplementations / class_replaceMethod let attackers (or
Cycript) hot-patch any selector. App should at minimum log / detect
modification of critical selectors. MASVS-RESILIENCE-5."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.method_swizzling_audit_findings import METHOD_SWIZZLING_AUDIT_FINDING_RULES

router = APIRouter()
SWIZZLE_API_RE = re.compile(r'method_exchangeImplementations|class_replaceMethod|method_setImplementation')
RUNTIME_INTROSPECT_RE = re.compile(r'class_getMethodImplementation|method_getImplementation|method_getName')
SWIFT_DYNAMIC_RE = re.compile(r'@objc\s+dynamic|dynamic\s+var')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["method_swizzling_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["method_swizzling_audit_error"] = str(e); return
    is_ios = False
    swizzle_users = []
    introspect_users = []
    swift_dynamic = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".swift", ".m", ".mm", ".h"): continue
        is_ios = True
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if SWIZZLE_API_RE.search(txt) and len(swizzle_users) < 20:
            swizzle_users.append(p.name)
        if RUNTIME_INTROSPECT_RE.search(txt) and len(introspect_users) < 20:
            introspect_users.append(p.name)
        if SWIFT_DYNAMIC_RE.search(txt) and len(swift_dynamic) < 30:
            swift_dynamic.append(p.name)
    findings_total = 0
    # Swizzle APIs present without runtime introspection = no defense check
    if swizzle_users and not introspect_users:
        findings_total += 1
    # No introspection at all = no swizzle-detection baseline
    if is_ios and not introspect_users:
        findings_total += 1 if not findings_total else findings_total
    ctx.state["is_ios"] = is_ios
    ctx.state["swizzle_users"] = swizzle_users
    ctx.state["introspect_users"] = introspect_users
    ctx.state["swift_dynamic_attrs"] = swift_dynamic
    ctx.state["files_scanned"] = files_scanned
    ctx.state["method_swizzling_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Swizzle API users", "swizzle_users"),
                ("Runtime introspection", "introspect_users"),
                ("Swift @objc dynamic", "swift_dynamic_attrs"),
                ("iOS detected", "is_ios")]


@router.post("/api/mobile_runtime/method_swizzling_audit")
async def mobile_runtime_method_swizzling_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="method_swizzling_audit",
        gather_func=gather, finding_rules=METHOD_SWIZZLING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
