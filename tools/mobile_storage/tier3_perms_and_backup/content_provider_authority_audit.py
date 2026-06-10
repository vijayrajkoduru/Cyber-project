"""content_provider_authority_audit - exported Android ContentProvider exposure.

<provider android:exported="true"> without grantUriPermissions or path-permission
filter exposes the backing DB / files to any installed app. MASVS-STORAGE-2,
common Android IDOR class."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.content_provider_authority_audit_findings import CONTENT_PROVIDER_AUTHORITY_AUDIT_FINDING_RULES

router = APIRouter()
PROVIDER_RE = re.compile(r'<provider[^>]+android:exported="true"[^>]*>', re.IGNORECASE)
AUTHORITY_RE = re.compile(r'android:authorities="([^"]+)"')
GRANT_URI_RE = re.compile(r'android:grantUriPermissions="true"')
PERM_RE = re.compile(r'android:(?:readPermission|writePermission|permission)="([^"]+)"')
PATH_PERM_RE = re.compile(r'<path-permission|<grant-uri-permission')
SCAN_MAX_FILES = 1000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["content_provider_authority_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["content_provider_authority_audit_error"] = str(e); return
    exposed = []
    files_scanned = 0
    for p in unpacked.rglob("*.xml"):
        if files_scanned >= SCAN_MAX_FILES: break
        if "AndroidManifest" not in p.name and "manifest" not in p.name.lower(): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        for m in PROVIDER_RE.finditer(txt):
            block = m.group(0)
            auth_m = AUTHORITY_RE.search(block)
            authority = auth_m.group(1) if auth_m else "(unknown)"
            has_perm = bool(PERM_RE.search(block))
            has_path = bool(PATH_PERM_RE.search(block))
            if not has_perm and not has_path:
                exposed.append({"authority": authority[:80], "file": p.name})
            if len(exposed) >= 25: break
    findings_total = 1 if exposed else 0
    ctx.state["exposed_providers"] = exposed
    ctx.state["files_scanned"] = files_scanned
    ctx.state["content_provider_authority_audit_total"] = findings_total
    ctx.source(f"{files_scanned} manifests")


INTEL_FIELDS = [("Exported providers (no permission)", "exposed_providers")]


@router.post("/api/mobile_storage/content_provider_authority_audit")
async def mobile_storage_content_provider_authority_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="content_provider_authority_audit",
        gather_func=gather, finding_rules=CONTENT_PROVIDER_AUTHORITY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
