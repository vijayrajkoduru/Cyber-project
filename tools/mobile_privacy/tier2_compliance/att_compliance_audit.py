"""att_compliance_audit - Apple App Tracking Transparency (ATT) compliance.

iOS 14.5+ requires ATTrackingManager.requestTrackingAuthorization before
accessing IDFA. Detects: IDFA usage without ATT request; NSUserTracking-
UsageDescription missing in Info.plist. MASVS-PRIVACY-4 / Apple ATT."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.att_compliance_audit_findings import ATT_COMPLIANCE_AUDIT_FINDING_RULES

router = APIRouter()
IDFA_USE_RE = re.compile(r'advertisingIdentifier|ASIdentifierManager|kCFBundleIdentifier|IDFA')
ATT_REQUEST_RE = re.compile(r'ATTrackingManager\.requestTrackingAuthorization|requestTrackingAuthorizationWithCompletionHandler')
NSUTUD_RE = re.compile(r'<key>NSUserTrackingUsageDescription</key>')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["att_compliance_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["att_compliance_audit_error"] = str(e); return
    is_ios = False
    idfa_users = []
    att_callers = 0
    has_nsutud = False
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file(): continue
        if p.suffix == ".plist":
            is_ios = True
            try: txt = p.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError): continue
            files_scanned += 1
            if NSUTUD_RE.search(txt): has_nsutud = True
            continue
        if p.suffix not in (".swift", ".m", ".h"): continue
        is_ios = True
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if IDFA_USE_RE.search(txt) and len(idfa_users) < 20: idfa_users.append(p.name)
        if ATT_REQUEST_RE.search(txt): att_callers += 1
    findings_total = 0
    if is_ios and idfa_users and att_callers == 0: findings_total += 1
    if is_ios and idfa_users and not has_nsutud: findings_total += 1
    ctx.state["is_ios"] = is_ios
    ctx.state["idfa_users"] = idfa_users
    ctx.state["att_request_callers"] = att_callers
    ctx.state["nsusertrackingusagedescription_present"] = has_nsutud
    ctx.state["files_scanned"] = files_scanned
    ctx.state["att_compliance_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("iOS detected", "is_ios"),
                ("IDFA users", "idfa_users"),
                ("ATT request callers", "att_request_callers"),
                ("NSUserTrackingUsageDescription present", "nsusertrackingusagedescription_present")]


@router.post("/api/mobile_privacy/att_compliance_audit")
async def mobile_privacy_att_compliance_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="att_compliance_audit",
        gather_func=gather, finding_rules=ATT_COMPLIANCE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
