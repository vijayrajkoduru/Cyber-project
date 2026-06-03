"""privacy_manifest_audit - Apple Privacy Manifest (PrivacyInfo.xcprivacy).
Required since iOS 17 for App Store submission. Detects file presence
+ required-reason API declarations + tracking domains."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.privacy_manifest_audit_findings import PRIVACY_MANIFEST_AUDIT_FINDING_RULES

router = APIRouter()
REQUIRED_REASON_APIS = [
    ("UserDefaults", r"NSUserDefaults|UserDefaults\."),
    ("FileTimestamp", r"NSURLCreationDateKey|fileModificationDate"),
    ("SystemBootTime", r"systemUptime|kern\.boottime"),
    ("DiskSpace", r"NSURLVolumeAvailableCapacityKey"),
    ("ActiveKeyboards", r"UITextInputMode\.activeInputModes"),
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["privacy_manifest_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["privacy_manifest_audit_error"] = str(e); return
    is_ios = False
    manifest_found = False
    code_blob = ""
    declared_apis = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= 5000: break
        if not p.is_file(): continue
        if p.name == "PrivacyInfo.xcprivacy":
            is_ios = True
            manifest_found = True
            try: man_txt = p.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError): continue
            files_scanned += 1
            declared_apis = re.findall(r'<string>([A-Z][A-Za-z]+)</string>', man_txt)
            continue
        if p.suffix in (".swift", ".m", ".h", ".plist"):
            is_ios = True
            try: code_blob += p.read_text(errors="ignore")[:6000]
            except (OSError, UnicodeDecodeError): continue
            files_scanned += 1
    used_apis = []
    for api_name, pattern in REQUIRED_REASON_APIS:
        if re.search(pattern, code_blob):
            used_apis.append(api_name)
    missing_declarations = [a for a in used_apis if a not in declared_apis]
    findings_total = 0
    if is_ios and not manifest_found: findings_total += 1
    if missing_declarations: findings_total += 1
    ctx.state["is_ios"] = is_ios
    ctx.state["privacy_manifest_found"] = manifest_found
    ctx.state["required_reason_apis_used"] = used_apis
    ctx.state["missing_required_reason_declarations"] = missing_declarations
    ctx.state["files_scanned"] = files_scanned
    ctx.state["privacy_manifest_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("iOS detected", "is_ios"),
                ("PrivacyInfo.xcprivacy found", "privacy_manifest_found"),
                ("Required-reason APIs used", "required_reason_apis_used"),
                ("Missing declarations", "missing_required_reason_declarations")]


@router.post("/api/mobile_privacy/privacy_manifest_audit")
async def mobile_privacy_privacy_manifest_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="privacy_manifest_audit",
        gather_func=gather, finding_rules=PRIVACY_MANIFEST_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
