"""mutual_tls_audit - mTLS client-certificate handling.
Android: KeyManagerFactory + PKCS12 import. iOS: NSURLAuthenticationMethodClientCertificate
+ SecPKCS12Import. Detects presence + secure key storage handoff."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.mutual_tls_audit_findings import MUTUAL_TLS_AUDIT_FINDING_RULES

router = APIRouter()
ANDROID_MTLS_RE = re.compile(r'KeyManagerFactory|X509KeyManager|KeyStore\.getInstance\("PKCS12"\)')
IOS_MTLS_RE = re.compile(r'NSURLAuthenticationMethodClientCertificate|SecPKCS12Import|SecIdentityCreate')
PKCS12_FILE_RE = re.compile(r'\.p12|\.pfx', re.IGNORECASE)
KEYSTORE_BACKED_RE = re.compile(r'AndroidKeyStore|kSecAttrAccessibleWhenUnlockedThisDeviceOnly')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["mutual_tls_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["mutual_tls_audit_error"] = str(e); return
    mtls_callers = []
    p12_resources = []
    keystore_backed = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file(): continue
        if p.suffix in (".p12", ".pfx") and len(p12_resources) < 25:
            p12_resources.append(str(p.relative_to(unpacked)))
            continue
        if p.suffix not in (".smali", ".swift", ".m", ".h", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if ANDROID_MTLS_RE.search(txt) or IOS_MTLS_RE.search(txt):
            if len(mtls_callers) < 25:
                mtls_callers.append(p.name)
        if PKCS12_FILE_RE.search(txt):
            if len(p12_resources) < 25 and p.name not in p12_resources:
                p12_resources.append(p.name)
        if KEYSTORE_BACKED_RE.search(txt): keystore_backed += 1
    findings_total = 0
    # P12 bundled as resource - private key in plain
    if p12_resources:
        findings_total += 1
    # mTLS used but no Keystore/Keychain backing
    if mtls_callers and keystore_backed == 0:
        findings_total += 1
    ctx.state["mtls_callers"] = mtls_callers
    ctx.state["p12_resources"] = p12_resources
    ctx.state["keystore_backed_callers"] = keystore_backed
    ctx.state["files_scanned"] = files_scanned
    ctx.state["mutual_tls_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("mTLS callers", "mtls_callers"),
                ("PKCS12 / .p12 resources", "p12_resources"),
                ("KeyStore-backed callers", "keystore_backed_callers")]


@router.post("/api/mobile_network/mutual_tls_audit")
async def mobile_network_mutual_tls_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="mutual_tls_audit",
        gather_func=gather, finding_rules=MUTUAL_TLS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
