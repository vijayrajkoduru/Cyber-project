"""keystore_keychain_audit - secure-element key storage posture.

Android: AndroidKeyStore provider usage + setUserAuthenticationRequired
         + setInvalidatedByBiometricEnrollment for biometric-backed keys.
iOS:     Keychain kSecAttrAccessible* level (avoid Always / AfterFirstUnlock
         for sensitive keys) + kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly.
MSTG-STORAGE-1, MSTG-STORAGE-11."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.keystore_keychain_audit_findings import KEYSTORE_KEYCHAIN_AUDIT_FINDING_RULES

router = APIRouter()

ANDROID_KEYSTORE_RE = re.compile(r"AndroidKeyStore")
ANDROID_USER_AUTH_RE = re.compile(r"setUserAuthenticationRequired\s*\(\s*true\s*\)")
ANDROID_INVALIDATE_BIO_RE = re.compile(r"setInvalidatedByBiometricEnrollment\s*\(\s*true\s*\)")

IOS_KEYCHAIN_USE_RE = re.compile(r"SecItemAdd|SecItemCopyMatching|kSecClassGenericPassword|kSecClassInternetPassword")
IOS_ACCESSIBLE_WEAK_RE = re.compile(
    r"kSecAttrAccessibleAlways|kSecAttrAccessibleAfterFirstUnlock\b(?!ThisDeviceOnly)"
)
IOS_ACCESSIBLE_STRONG_RE = re.compile(
    r"kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly|kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["keystore_keychain_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["keystore_keychain_audit_error"] = str(e)
        return

    android_keystore_files = []
    android_user_auth_files = 0
    android_invalidate_files = 0
    ios_keychain_files = []
    ios_weak_access_files = []
    ios_strong_access_files = 0
    files_scanned = 0

    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".mm", ".h"):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        if ANDROID_KEYSTORE_RE.search(txt):
            if len(android_keystore_files) < 25:
                android_keystore_files.append(p.name)
            if ANDROID_USER_AUTH_RE.search(txt):
                android_user_auth_files += 1
            if ANDROID_INVALIDATE_BIO_RE.search(txt):
                android_invalidate_files += 1

        if IOS_KEYCHAIN_USE_RE.search(txt):
            if len(ios_keychain_files) < 25:
                ios_keychain_files.append(p.name)
            if IOS_ACCESSIBLE_WEAK_RE.search(txt):
                if len(ios_weak_access_files) < 25:
                    ios_weak_access_files.append(p.name)
            if IOS_ACCESSIBLE_STRONG_RE.search(txt):
                ios_strong_access_files += 1

    findings_total = 0
    # Android: any AndroidKeyStore use but no user-auth gate on any of them
    if android_keystore_files and android_user_auth_files == 0:
        findings_total += 1
    # iOS: keychain use with weak accessible level
    if ios_weak_access_files:
        findings_total += 1
    # iOS: no keychain at all but app stores credentials somewhere else
    # (intentionally weak signal — only fire when files_scanned is solid)

    ctx.state["android_keystore_files"] = android_keystore_files
    ctx.state["android_user_auth_files"] = android_user_auth_files
    ctx.state["android_invalidate_files"] = android_invalidate_files
    ctx.state["ios_keychain_files"] = ios_keychain_files
    ctx.state["ios_weak_access_files"] = ios_weak_access_files
    ctx.state["ios_strong_access_files"] = ios_strong_access_files
    ctx.state["files_scanned"] = files_scanned
    ctx.state["keystore_keychain_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [
    ("AndroidKeyStore users", "android_keystore_files"),
    ("Android user-auth gated", "android_user_auth_files"),
    ("Android biometric-invalidated", "android_invalidate_files"),
    ("iOS Keychain users", "ios_keychain_files"),
    ("iOS weak kSecAttrAccessible", "ios_weak_access_files"),
    ("iOS strong kSecAttrAccessible", "ios_strong_access_files"),
]


@router.post("/api/mobile_storage/keystore_keychain_audit")
async def mobile_storage_keystore_keychain_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="keystore_keychain_audit",
        gather_func=gather,
        finding_rules=KEYSTORE_KEYCHAIN_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
