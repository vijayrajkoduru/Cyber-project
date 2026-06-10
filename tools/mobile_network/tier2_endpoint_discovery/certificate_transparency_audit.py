"""certificate_transparency_audit - SCT / CT validation.

Android: NetworkSecurityConfig <certificate-transparency> or library
references (conscrypt, okhttp-tls). iOS: ATS NSRequiresCertificateTransparency.
Mitigates rogue-CA issuance. MSTG-NETWORK-4."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.certificate_transparency_audit_findings import CERTIFICATE_TRANSPARENCY_AUDIT_FINDING_RULES

router = APIRouter()
NSC_CT_RE = re.compile(r'<certificate-transparency|certificateTransparencyVerification', re.IGNORECASE)
ANDROID_CT_LIB_RE = re.compile(r'conscrypt|CertificateTransparency|certificate-transparency-android')
IOS_CT_RE = re.compile(r'NSRequiresCertificateTransparency\s*</key>\s*<true|NSRequiresCertificateTransparency\s*=\s*true', re.IGNORECASE)
TLS_USE_RE = re.compile(r'OkHttpClient|HttpURLConnection|URLSession|NSURLSession')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["certificate_transparency_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["certificate_transparency_audit_error"] = str(e); return
    ct_evidence = []
    tls_clients = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".xml", ".plist", ".smali", ".swift", ".m"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if NSC_CT_RE.search(txt) or ANDROID_CT_LIB_RE.search(txt) or IOS_CT_RE.search(txt):
            if len(ct_evidence) < 20:
                ct_evidence.append(p.name)
        if TLS_USE_RE.search(txt) and len(tls_clients) < 20:
            tls_clients.append(p.name)
    findings_total = 0
    if tls_clients and not ct_evidence:
        findings_total += 1
    ctx.state["ct_evidence_files"] = ct_evidence
    ctx.state["tls_client_files"] = tls_clients
    ctx.state["files_scanned"] = files_scanned
    ctx.state["certificate_transparency_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("CT evidence files", "ct_evidence_files"),
                ("TLS client files", "tls_client_files")]


@router.post("/api/mobile_network/certificate_transparency_audit")
async def mobile_network_certificate_transparency_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="certificate_transparency_audit",
        gather_func=gather, finding_rules=CERTIFICATE_TRANSPARENCY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
