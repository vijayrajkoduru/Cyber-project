"""auth_token_storage_audit — where the app stores auth tokens.

Auth tokens (Bearer / refresh_token / session_id) should live in:
  - Android EncryptedSharedPreferences or Keystore
  - iOS Keychain
NOT in plain SharedPreferences / NSUserDefaults / files.

Static check: detect token-related variable names + which storage API
they end up in. Heuristic — false negatives possible but the pattern
catches the obvious anti-patterns.

MASVS-STORAGE-1 / MSTG-STORAGE-1.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.auth_token_storage_audit_findings import \
    AUTH_TOKEN_STORAGE_AUDIT_FINDING_RULES

router = APIRouter()

INSECURE_STORAGE_MARKERS = [
    b"getSharedPreferences",         # Android — not encrypted by default
    b"PreferenceManager",
    b"NSUserDefaults",                # iOS — not encrypted
    b"NSDictionary writeToFile",
    b"FileOutputStream",
    b"openFileOutput",
]

SECURE_STORAGE_MARKERS = [
    b"EncryptedSharedPreferences",   # Android — Jetpack Security
    b"AndroidKeyStore",
    b"Landroid/security/keystore",
    b"keychain", b"SecItemAdd",       # iOS Keychain
    b"kSecClass", b"kSecAttrAccessible",
    b"BiometricPrompt$AuthenticatorCallback",  # crypto-object binding
]

TOKEN_NAME_MARKERS = [
    b"auth_token", b"authToken", b"access_token", b"accessToken",
    b"refresh_token", b"refreshToken", b"session_id", b"sessionId",
    b"Bearer", b"AUTHORIZATION", b"X-Auth-Token", b"jwt_token",
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["auth_token_storage_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["auth_token_storage_audit_error"] = str(e); return

    insecure_files = []
    secure_files = []
    token_files = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        has_token = any(m in data for m in TOKEN_NAME_MARKERS)
        if not has_token: continue
        token_files.append(f.relative_to(unpacked).as_posix())
        has_insecure = any(m in data for m in INSECURE_STORAGE_MARKERS)
        has_secure   = any(m in data for m in SECURE_STORAGE_MARKERS)
        if has_insecure and not has_secure:
            insecure_files.append(f.relative_to(unpacked).as_posix())
        elif has_secure:
            secure_files.append(f.relative_to(unpacked).as_posix())

    ctx.state["token_files"] = token_files[:30]
    ctx.state["insecure_token_storage_files"] = insecure_files[:15]
    ctx.state["secure_token_storage_files"] = secure_files[:15]
    ctx.state["auth_token_storage_audit_total"] = len(insecure_files)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned}, tokens in {len(token_files)} files, "
                f"insecure {len(insecure_files)}, secure {len(secure_files)}")


INTEL_FIELDS = [
    ("Token-mentioning files",       "token_files"),
    ("Insecure-storage flow files",  "insecure_token_storage_files"),
    ("Secure-storage flow files",    "secure_token_storage_files"),
    ("Files scanned",                "files_scanned"),
]


@router.post("/api/mobile_static/auth_token_storage_audit")
async def mobile_static_auth_token_storage_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="auth_token_storage_audit",
        gather_func=gather,
        finding_rules=AUTH_TOKEN_STORAGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
