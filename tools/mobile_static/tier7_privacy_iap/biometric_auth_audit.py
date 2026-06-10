"""biometric_auth_audit — detect biometric authentication usage.

Modern apps handling sensitive data should use BiometricPrompt (Android
API 28+) or LocalAuthentication (iOS) rather than relying on password
alone. Detects use and flags deprecated APIs (FingerprintManager).
MASVS-AUTH-2 / MSTG-AUTH-8.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.biometric_auth_audit_findings import \
    BIOMETRIC_AUTH_AUDIT_FINDING_RULES

router = APIRouter()

MODERN_MARKERS = [
    (b"Landroidx/biometric/BiometricPrompt", "AndroidX BiometricPrompt"),
    (b"Landroidx/biometric/",                 "AndroidX biometric package"),
    (b"Landroid/hardware/biometrics/BiometricPrompt", "Platform BiometricPrompt"),
    # iOS
    (b"LocalAuthentication.framework",         "iOS LocalAuthentication"),
    (b"LAContext",                              "iOS LAContext"),
    (b"evaluatePolicy:localizedReason",         "iOS biometric evaluatePolicy"),
]

DEPRECATED_MARKERS = [
    (b"Landroid/hardware/fingerprint/FingerprintManager", "FingerprintManager (deprecated)"),
    (b"Landroid/security/keystore/KeyGenParameterSpec$Builder", None),  # not deprecated, just trace
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["biometric_auth_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["biometric_auth_audit_error"] = str(e); return

    modern = []
    deprecated = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for marker, name in MODERN_MARKERS:
            if marker in data and name not in [m["name"] for m in modern]:
                modern.append({"name": name, "marker": marker.decode(errors="ignore")})
        for marker, name in DEPRECATED_MARKERS:
            if name is None: continue
            if marker in data and name not in [d["name"] for d in deprecated]:
                deprecated.append({"name": name, "marker": marker.decode(errors="ignore")})

    ctx.state["biometric_modern_found"] = modern
    ctx.state["biometric_deprecated_found"] = deprecated
    ctx.state["biometric_auth_audit_total"] = len(modern) + len(deprecated)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} files")


INTEL_FIELDS = [
    ("Modern biometric APIs",     "biometric_modern_found"),
    ("Deprecated biometric APIs", "biometric_deprecated_found"),
    ("Files scanned",              "files_scanned"),
]


@router.post("/api/mobile_static/biometric_auth_audit")
async def mobile_static_biometric_auth_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="biometric_auth_audit",
        gather_func=gather,
        finding_rules=BIOMETRIC_AUTH_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
