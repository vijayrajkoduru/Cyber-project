"""pii_in_logs_audit - PII patterns in Log.d/NSLog calls.
Detects log calls containing or referencing email, phone, IMEI, IDFA,
GAID, social security format. MASVS-PRIVACY-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.pii_in_logs_audit_findings import PII_IN_LOGS_AUDIT_FINDING_RULES

router = APIRouter()
LOG_CALL_RE = re.compile(r'Log\.[dievwt]\s*\(|NSLog\s*\(|print\(|os_log|os\.log')
PII_NEAR_LOG_RE = re.compile(r'(email|phone|imei|idfa|gaid|aaid|ssn|passport|address|userid)', re.IGNORECASE)
EMAIL_LITERAL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["pii_in_logs_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["pii_in_logs_audit_error"] = str(e); return
    pii_log_files = []
    email_literals = []
    log_users = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if LOG_CALL_RE.search(txt):
            log_users += 1
            if PII_NEAR_LOG_RE.search(txt) and len(pii_log_files) < 20:
                pii_log_files.append(p.name)
        for m in EMAIL_LITERAL_RE.finditer(txt):
            if len(email_literals) < 10 and "@example" not in m.group(0).lower():
                email_literals.append(m.group(0))
    findings_total = 0
    if pii_log_files: findings_total += 1
    if email_literals: findings_total += 1
    ctx.state["pii_in_log_files"] = pii_log_files
    ctx.state["email_literals_found"] = email_literals
    ctx.state["log_users"] = log_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["pii_in_logs_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("PII near log calls", "pii_in_log_files"),
                ("Email literals found", "email_literals_found"),
                ("Log callers", "log_users")]


@router.post("/api/mobile_privacy/pii_in_logs_audit")
async def mobile_privacy_pii_in_logs_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="pii_in_logs_audit",
        gather_func=gather, finding_rules=PII_IN_LOGS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
