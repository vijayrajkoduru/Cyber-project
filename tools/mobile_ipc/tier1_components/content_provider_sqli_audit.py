"""content_provider_sqli_audit - ContentProvider SQLi + path-traversal.

query(uri, projection, selection, args) with `selection` built from caller
input via string concat is classic CP-SQLi. CP path traversal via
openFile(uri) without canonicalization. MASVS-PLATFORM-2."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.content_provider_sqli_audit_findings import CONTENT_PROVIDER_SQLI_AUDIT_FINDING_RULES

router = APIRouter()
# Capture the SELECTION argument of query(uri, projection, selection, ...).
# We then test concat *on that argument specifically* rather than anywhere in
# the file (a StringBuilder elsewhere is not CP-SQLi). presence != usage.
CP_QUERY_SEL_RE = re.compile(
    r'\.query\s*\(\s*[^,]+,\s*[^,]+,\s*([^,]+?)\s*,', re.DOTALL)
# Smali idiom: query() takes the selection as a register; concat is visible as
# StringBuilder->append feeding the selection register near the call site.
SEL_CONCAT_RE = re.compile(
    r'(\+\s*[\w.\[\]()]+\s*\+|'                       # "WHERE id=" + x + ...
    r'String\.format\s*\(|'                            # String.format on selection
    r'StringBuilder.*?append.*?toString|'             # built selection string
    r'concat\s*\()', re.DOTALL | re.IGNORECASE)
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
        # Require concat to be on the captured selection arg, and require a
        # ContentProvider context (defining a provider, not merely querying one).
        is_provider = ("contentprovider" in txt.lower()
                       or "extends android.content.ContentProvider" in txt
                       or "Landroid/content/ContentProvider;" in txt)
        if is_provider:
            for qm in CP_QUERY_SEL_RE.finditer(txt):
                sel_arg = qm.group(1) or ""
                # Inspect the selection argument plus a small window after the
                # call so smali register-built selections are caught, but a
                # constant/parameterized selection ("?") is not flagged.
                window = txt[qm.start():qm.start() + 600]
                if "?" in sel_arg and not SEL_CONCAT_RE.search(sel_arg):
                    continue  # parameterized selection -> safe
                if SEL_CONCAT_RE.search(sel_arg) or SEL_CONCAT_RE.search(window):
                    if p.name not in sqli_suspects and len(sqli_suspects) < 20:
                        sqli_suspects.append(p.name)
                    break
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
