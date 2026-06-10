"""dyld_insert_library_audit - iOS DYLD_INSERT_LIBRARIES tampering check.

iOS apps signed with get-task-allow=true are still loadable with
DYLD_INSERT_LIBRARIES = libCheckra1n.dylib (or similar) via environment-
variable injection. Detect:
 - environ inspection (getenv("DYLD_INSERT_LIBRARIES"))
 - dyld_image_count / _dyld_get_image_name verification at startup
MASVS-RESILIENCE-2."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.dyld_insert_library_audit_findings import DYLD_INSERT_LIBRARY_AUDIT_FINDING_RULES

router = APIRouter()
ENV_CHECK_RE = re.compile(r'DYLD_INSERT_LIBRARIES|DYLD_PRINT_LIBRARIES|getenv\("DYLD_')
IMAGE_INSPECTION_RE = re.compile(r'_dyld_image_count|_dyld_get_image_name|dyld_get_program_sdk_version')
SUSPICIOUS_LIBS_RE = re.compile(r'/usr/lib/lib(?:Cycript|Checkra1n|Substrate|substitute)\.dylib|MobileSubstrate')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["dyld_insert_library_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["dyld_insert_library_audit_error"] = str(e); return
    is_ios = False
    env_callers = []
    image_callers = []
    suspect_lib_strings = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file(): continue
        if p.suffix in (".swift", ".m", ".mm", ".h"):
            is_ios = True
            try: txt = p.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError): continue
            files_scanned += 1
            if ENV_CHECK_RE.search(txt) and len(env_callers) < 20:
                env_callers.append(p.name)
            if IMAGE_INSPECTION_RE.search(txt) and len(image_callers) < 20:
                image_callers.append(p.name)
            if SUSPICIOUS_LIBS_RE.search(txt) and len(suspect_lib_strings) < 20:
                suspect_lib_strings.append(p.name)
        elif p.suffix == ".dylib":
            is_ios = True
            files_scanned += 1
    findings_total = 0
    if is_ios and not env_callers and not image_callers:
        findings_total += 1
    ctx.state["is_ios"] = is_ios
    ctx.state["env_inspection_callers"] = env_callers
    ctx.state["image_inspection_callers"] = image_callers
    ctx.state["suspicious_lib_strings"] = suspect_lib_strings
    ctx.state["files_scanned"] = files_scanned
    ctx.state["dyld_insert_library_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("iOS detected", "is_ios"),
                ("DYLD env-var checks", "env_inspection_callers"),
                ("dyld image-list checks", "image_inspection_callers"),
                ("Suspicious dylib refs", "suspicious_lib_strings")]


@router.post("/api/mobile_runtime/dyld_insert_library_audit")
async def mobile_runtime_dyld_insert_library_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="dyld_insert_library_audit",
        gather_func=gather, finding_rules=DYLD_INSERT_LIBRARY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
