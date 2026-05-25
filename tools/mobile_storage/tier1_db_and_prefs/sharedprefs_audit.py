"""sharedprefs_audit — static analysis of SharedPreferences usage in decompiled
APK. Detects: (a) plain (unencrypted) SharedPreferences usage,
(b) absence of EncryptedSharedPreferences when sensitive keys present,
(c) sensitive key names (token/password/jwt/auth/session/api_key)."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.sharedprefs_audit_findings import SHAREDPREFS_AUDIT_FINDING_RULES

router = APIRouter()

SENSITIVE_KEY_RE = re.compile(
    r'"([^"]{3,40})"', re.IGNORECASE)
SENSITIVE_HINTS = ("token", "password", "passwd", "pwd", "jwt", "auth",
                    "session", "api_key", "apikey", "secret", "credential",
                    "pin", "otp", "private_key", "access_token", "refresh_token")
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["sharedprefs_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["sharedprefs_audit_error"] = str(e)
        return

    plain_call_files = []
    encrypted_call_files = []
    sensitive_keys = []
    files_scanned = 0

    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        # Plain SharedPreferences references
        if "getSharedPreferences" in txt or "PreferenceManager" in txt:
            if len(plain_call_files) < 20:
                plain_call_files.append(p.name)
            # Look for sensitive-looking key literals in same file
            for m in SENSITIVE_KEY_RE.finditer(txt):
                k = m.group(1).lower()
                if any(h in k for h in SENSITIVE_HINTS) and m.group(1) not in sensitive_keys:
                    sensitive_keys.append(m.group(1))
                    if len(sensitive_keys) >= 25:
                        break

        # EncryptedSharedPreferences (AndroidX Security) — good pattern
        if "EncryptedSharedPreferences" in txt or "MasterKey" in txt:
            if len(encrypted_call_files) < 20:
                encrypted_call_files.append(p.name)

    findings_total = 0
    if plain_call_files and not encrypted_call_files:
        findings_total += 1  # plain prefs with no encrypted alternative
    if sensitive_keys:
        findings_total += 1

    ctx.state["plain_prefs_files"] = plain_call_files
    ctx.state["encrypted_prefs_files"] = encrypted_call_files
    ctx.state["sensitive_pref_keys"] = sensitive_keys
    ctx.state["files_scanned"] = files_scanned
    ctx.state["sharedprefs_audit_total"] = findings_total
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Plain pref files", "plain_prefs_files"),
    ("Encrypted pref files", "encrypted_prefs_files"),
    ("Sensitive keys", "sensitive_pref_keys"),
]


@router.post("/api/mobile_storage/sharedprefs_audit")
async def mobile_storage_sharedprefs_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="sharedprefs_audit",
        gather_func=gather,
        finding_rules=SHAREDPREFS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
