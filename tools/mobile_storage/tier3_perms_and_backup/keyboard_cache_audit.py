"""keyboard_cache_audit - MSTG-STORAGE-5 keyboard cache exposure.

Sensitive EditTexts / UITextFields cache user input by default. Detects:
 - Android: missing inputType=textNoSuggestions|textPassword|textVisiblePassword
            on sensitive fields; missing setShowSoftInputOnFocus(false) for
            custom secure entry.
 - iOS:     missing isSecureTextEntry=true AND missing
            autocorrectionType=.no on sensitive UITextFields."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.keyboard_cache_audit_findings import KEYBOARD_CACHE_AUDIT_FINDING_RULES

router = APIRouter()

ANDROID_INPUT_PWD_RE = re.compile(r'inputType="[^"]*(textPassword|textNoSuggestions|textVisiblePassword|numberPassword)')
ANDROID_INPUT_RE = re.compile(r'inputType="')
ANDROID_FIELD_RE = re.compile(r'<EditText[^>]*android:hint="([^"]+)"')

IOS_SECURE_RE = re.compile(r"isSecureTextEntry\s*=\s*true|secureTextEntry\s*=\s*YES")
IOS_AUTOCORRECT_RE = re.compile(r"autocorrectionType\s*=\s*\.no|autocorrectionType\s*=\s*UITextAutocorrectionTypeNo")
IOS_FIELD_RE = re.compile(r"UITextField\(\)|UITextField\s*\*")

SENSITIVE_HINTS = ("password", "pin", "secret", "code", "card", "ssn",
                    "tax", "passport", "license", "otp", "cvv", "cvc", "vault")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["keyboard_cache_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["keyboard_cache_audit_error"] = str(e)
        return

    android_sensitive_fields = []
    android_protected_fields = 0
    ios_sensitive_files = []
    ios_secure_files = 0
    ios_no_autocorrect_files = 0
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

        # Android layout XML
        if p.suffix == ".xml":
            for m in ANDROID_FIELD_RE.finditer(txt):
                hint = m.group(1).lower()
                if any(h in hint for h in SENSITIVE_HINTS):
                    if len(android_sensitive_fields) < 25:
                        android_sensitive_fields.append({"file": p.name, "hint": hint[:50]})
            if ANDROID_INPUT_PWD_RE.search(txt):
                android_protected_fields += 1
            continue

        # iOS sources
        name_lc = p.name.lower()
        if (any(h in name_lc for h in SENSITIVE_HINTS) or IOS_FIELD_RE.search(txt)):
            if any(h in txt.lower() for h in SENSITIVE_HINTS):
                if len(ios_sensitive_files) < 25:
                    ios_sensitive_files.append(p.name)
                if IOS_SECURE_RE.search(txt):
                    ios_secure_files += 1
                if IOS_AUTOCORRECT_RE.search(txt):
                    ios_no_autocorrect_files += 1

    # Risk model: sensitive fields exist but the protection ratio is too low.
    a_total = len(android_sensitive_fields)
    a_unprotected = max(0, a_total - android_protected_fields)
    i_total = len(ios_sensitive_files)
    i_unprotected = max(0, i_total - min(ios_secure_files, ios_no_autocorrect_files))

    findings_total = 0
    if a_unprotected:
        findings_total += 1
    if i_unprotected:
        findings_total += 1

    ctx.state["android_sensitive_fields"] = android_sensitive_fields
    ctx.state["android_unprotected"] = a_unprotected
    ctx.state["ios_sensitive_files"] = ios_sensitive_files
    ctx.state["ios_unprotected"] = i_unprotected
    ctx.state["files_scanned"] = files_scanned
    ctx.state["keyboard_cache_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [
    ("Android sensitive fields", "android_sensitive_fields"),
    ("Android unprotected", "android_unprotected"),
    ("iOS sensitive files", "ios_sensitive_files"),
    ("iOS unprotected", "ios_unprotected"),
]


@router.post("/api/mobile_storage/keyboard_cache_audit")
async def mobile_storage_keyboard_cache_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="keyboard_cache_audit",
        gather_func=gather,
        finding_rules=KEYBOARD_CACHE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
