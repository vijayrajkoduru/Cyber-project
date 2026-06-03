"""content_provider_sqli_audit - ContentProvider SQLi + path-traversal.

query(uri, projection, selection, args) with `selection` built from caller
input via string concat is classic CP-SQLi. CP path traversal via
openFile(uri) without canonicalization. MASVS-PLATFORM-2."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.content_provider_sqli_audit_findings import CONTENT_PROVIDER_SQLI_AUDIT_FINDING_RULES

router = APIRouter()
CP_QUERY_RE = re.compile(r'\.query\s*\(\s*[^,]+,\s*[^,]+,\s*([^,)]+)', re.DOTALL)
SQL_CONCAT_RE = re.compile(r'(\+\s*\w+\s*\+|String\.format\s*\(|StringBuilder\.append)')
CP_PATH_RE = re.compile(r'openFile\s*\([^)]*\)|openAssetFile|getFileStreamPath')
CANONICALIZE_RE = re.compile(r'getCanonicalPath|getCanonicalFile|normalize\(\)')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["content_provider_sqli_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["content_provider_sqli_audit_error"] = str(e); return
    sqli_suspects = []
    traversal_suspects = []
    canonicalize_count = 0
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES: break
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if CP_QUERY_RE.search(txt) and SQL_CONCAT_RE.search(txt):
            if "contentprovider" in txt.lower() or "ContentResolver" in txt:
                if len(sqli_suspects) < 20:
                    sqli_suspects.append(p.name)
        if CP_PATH_RE.search(txt):
            if "contentprovider" in txt.lower() or "openFile" in txt:
                if len(traversal_suspects) < 20:
                    traversal_suspects.append(p.name)
        if CANONICALIZE_RE.search(txt):
            canonicalize_count += 1
    findings_total = 0
    if sqli_suspects: findings_total += 1
    if traversal_suspects and canonicalize_count == 0: findings_total += 1
    ctx.state["sqli_suspects"] = sqli_suspects
    ctx.state["path_traversal_suspects"] = traversal_suspects
    ctx.state["canonicalize_usage"] = canonicalize_count
    ctx.state["files_scanned"] = files_scanned
    ctx.state["content_provider_sqli_audit_total"] = findings_total
    ctx.source(f"{files_scanned} smali")


INTEL_FIELDS = [("SQLi suspect CP queries", "sqli_suspects"),
                ("Path-traversal suspects", "path_traversal_suspects"),
                ("Canonicalize callers", "canonicalize_usage")]


@router.post("/api/mobile_ipc/content_provider_sqli_audit")
async def mobile_ipc_content_provider_sqli_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="content_provider_sqli_audit",
        gather_func=gather, finding_rules=CONTENT_PROVIDER_SQLI_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
