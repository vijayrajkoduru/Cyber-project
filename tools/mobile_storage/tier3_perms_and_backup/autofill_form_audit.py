"""autofill_form_audit - autofill / form-cache exposure.

Android 8.0+ autofill framework caches form input unless the field declares
android:importantForAutofill="no" or autofillHints is set incorrectly.
iOS UITextField caches when textContentType is set to non-private values
(name, addressCity, etc.) on sensitive fields. MSTG-STORAGE-5 adjacent."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.autofill_form_audit_findings import AUTOFILL_FORM_AUDIT_FINDING_RULES

router = APIRouter()

ANDROID_AUTOFILL_OFF_RE = re.compile(r'importantForAutofill="(no|noExcludeDescendants)"')
ANDROID_AUTOFILL_HINTS_RE = re.compile(r'autofillHints="')
ANDROID_FIELD_RE = re.compile(r'<EditText[^>]*android:hint="([^"]+)"')
IOS_TEXT_CONTENT_RE = re.compile(r"textContentType\s*=\s*\.([a-zA-Z]+)|textContentType\s*=\s*UITextContentType([A-Z][a-zA-Z]+)")
SENSITIVE_HINTS = ("password", "pin", "card", "cvv", "cvc", "ssn", "secret",
                    "vault", "otp", "token", "tax")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["autofill_form_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["autofill_form_audit_error"] = str(e)
        return

    android_sensitive = []
    android_autofill_off = 0
    android_with_hints = 0
    ios_sensitive_files = []
    ios_textcontent_used = []
    files_scanned = 0

    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        if not p.is_file() or p.suffix not in (".xml", ".swift", ".m", ".h"):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        if p.suffix == ".xml":
            for m in ANDROID_FIELD_RE.finditer(txt):
                hint = m.group(1).lower()
                if any(h in hint for h in SENSITIVE_HINTS):
                    if len(android_sensitive) < 25:
                        android_sensitive.append({"file": p.name, "hint": hint[:50]})
            if ANDROID_AUTOFILL_OFF_RE.search(txt):
                android_autofill_off += 1
            if ANDROID_AUTOFILL_HINTS_RE.search(txt):
                android_with_hints += 1
            continue

        # iOS sources
        name_lc = p.name.lower()
        if any(h in name_lc for h in SENSITIVE_HINTS) or any(h in txt.lower() for h in SENSITIVE_HINTS):
            if len(ios_sensitive_files) < 25:
                ios_sensitive_files.append(p.name)
            for m in IOS_TEXT_CONTENT_RE.finditer(txt):
                kind = (m.group(1) or m.group(2) or "").lower()
                # Risky: non-secret textContentType on sensitive screen
                if kind and kind not in ("oneTimeCode", "newPassword", "password"):
                    ios_textcontent_used.append({"file": p.name, "type": kind})

    findings_total = 0
    a_unprot = max(0, len(android_sensitive) - android_autofill_off)
    if a_unprot:
        findings_total += 1
    if ios_textcontent_used:
        findings_total += 1

    ctx.state["android_sensitive"] = android_sensitive
    ctx.state["android_autofill_off"] = android_autofill_off
    ctx.state["android_unprotected"] = a_unprot
    ctx.state["ios_sensitive_files"] = ios_sensitive_files
    ctx.state["ios_textcontent_misuse"] = ios_textcontent_used[:20]
    ctx.state["files_scanned"] = files_scanned
    ctx.state["autofill_form_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [
    ("Android sensitive fields", "android_sensitive"),
    ("Android importantForAutofill=no", "android_autofill_off"),
    ("Android unprotected", "android_unprotected"),
    ("iOS textContentType misuse", "ios_textcontent_misuse"),
]


@router.post("/api/mobile_storage/autofill_form_audit")
async def mobile_storage_autofill_form_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="autofill_form_audit",
        gather_func=gather,
        finding_rules=AUTOFILL_FORM_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
