"""csp_trusted_types_audit - CSP + Trusted Types in WebView-loaded HTML."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.csp_trusted_types_audit_findings import CSP_TRUSTED_TYPES_AUDIT_FINDING_RULES

router = APIRouter()
CSP_META_RE = re.compile(r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\']', re.IGNORECASE)
CSP_UNSAFE_RE = re.compile(r"'unsafe-inline'|'unsafe-eval'", re.IGNORECASE)
TRUSTED_TYPES_RE = re.compile(r'require-trusted-types-for|trustedTypes\.createPolicy', re.IGNORECASE)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["csp_trusted_types_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["csp_trusted_types_audit_error"] = str(e); return
    csp_html, unsafe_csp = [], []
    trusted_types_uses = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".html", ".js"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if CSP_META_RE.search(txt) and len(csp_html) < 20:
            csp_html.append(p.name)
            if CSP_UNSAFE_RE.search(txt) and len(unsafe_csp) < 20: unsafe_csp.append(p.name)
        if TRUSTED_TYPES_RE.search(txt): trusted_types_uses += 1
    findings_total = 0
    if files_scanned > 5 and not csp_html: findings_total += 1
    if unsafe_csp: findings_total += 1
    ctx.state["html_files_with_csp"] = csp_html
    ctx.state["unsafe_csp_directives"] = unsafe_csp
    ctx.state["trusted_types_uses"] = trusted_types_uses
    ctx.state["files_scanned"] = files_scanned
    ctx.state["csp_trusted_types_audit_total"] = findings_total
    ctx.source(f"{files_scanned} html/js")


INTEL_FIELDS = [("HTML with CSP meta", "html_files_with_csp"),
                ("Unsafe CSP directives", "unsafe_csp_directives"),
                ("Trusted Types uses", "trusted_types_uses")]


@router.post("/api/mobile_webview/csp_trusted_types_audit")
async def mobile_webview_csp_trusted_types_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="csp_trusted_types_audit",
        gather_func=gather, finding_rules=CSP_TRUSTED_TYPES_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
