"""universal_clipboard_audit - iOS UIPasteboard Universal Clipboard / Handoff.

Sensitive copies (passwords, OTPs, payment data) sync to any signed-in
Apple device via iCloud Handoff unless UIPasteboard.local or .find is used.
Catches UIPasteboard.general with sensitive symbol co-location. MSTG-STORAGE-13."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.universal_clipboard_audit_findings import UNIVERSAL_CLIPBOARD_AUDIT_FINDING_RULES

router = APIRouter()
PASTEBOARD_GENERAL_RE = re.compile(r'UIPasteboard\.general|UIPasteboard pasteboardWithName:.*UIPasteboardNameGeneral')
PASTEBOARD_OPTS_RE = re.compile(r'\.localOnly|UIPasteboardOptionLocalOnly|setItems:options:.*localOnly')
EXPIRATION_RE = re.compile(r'UIPasteboardOptionExpirationDate|expirationDate:')
SENSITIVE_HINTS = ("token", "password", "secret", "otp", "code", "pin",
                    "card", "cvv", "cvc", "vault", "wallet", "key", "credential")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["universal_clipboard_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["universal_clipboard_audit_error"] = str(e); return
    pasteboard_users = []
    local_only = 0
    expiration_set = 0
    sensitive_co = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".swift", ".m", ".mm", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if PASTEBOARD_GENERAL_RE.search(txt):
            if len(pasteboard_users) < 25:
                pasteboard_users.append(p.name)
            if any(h in txt.lower() for h in SENSITIVE_HINTS):
                if len(sensitive_co) < 25 and p.name not in sensitive_co:
                    sensitive_co.append(p.name)
        if PASTEBOARD_OPTS_RE.search(txt): local_only += 1
        if EXPIRATION_RE.search(txt): expiration_set += 1
    findings_total = 0
    if sensitive_co:
        findings_total += 1
    elif pasteboard_users and local_only == 0:
        findings_total += 1
    ctx.state["pasteboard_users"] = pasteboard_users
    ctx.state["local_only_usage"] = local_only
    ctx.state["expiration_usage"] = expiration_set
    ctx.state["sensitive_co_located"] = sensitive_co
    ctx.state["files_scanned"] = files_scanned
    ctx.state["universal_clipboard_audit_total"] = findings_total
    ctx.source(f"{files_scanned} iOS files")


INTEL_FIELDS = [("UIPasteboard.general users", "pasteboard_users"),
                ("local-only callers", "local_only_usage"),
                ("expiration-date callers", "expiration_usage"),
                ("Sensitive co-located", "sensitive_co_located")]


@router.post("/api/mobile_storage/universal_clipboard_audit")
async def mobile_storage_universal_clipboard_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="universal_clipboard_audit",
        gather_func=gather, finding_rules=UNIVERSAL_CLIPBOARD_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
