"""cert_validation_bypass_audit (§4 #52) — find code that DISABLES certificate
validation, the #1 mobile TLS bug. Patterns: empty TrustManager.checkServerTrusted,
TrustAllX509TrustManager classes, ALLOW_ALL_HOSTNAME_VERIFIER, .setHostnameVerifier
returning true, custom SSLSocketFactory that accepts all certs."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.cert_validation_bypass_audit_findings import CERT_VALIDATION_BYPASS_AUDIT_FINDING_RULES
from tools._payloads.mobile._fp_gates import is_app_code_path, is_test_path

router = APIRouter()

BYPASS_PATTERNS = {
    "TrustAllX509TrustManager class": re.compile(r"TrustAllX509TrustManager|TrustAllTrustManager|TrustAllCerts", re.IGNORECASE),
    "Empty checkServerTrusted": re.compile(
        r'\.method.*?checkServerTrusted\([^)]*\)[^{]*?\n.*?\.locals\s+0[^.]*?\.end method',
        re.DOTALL),
    "ALLOW_ALL_HOSTNAME_VERIFIER": re.compile(r"ALLOW_ALL_HOSTNAME_VERIFIER"),
    "NaiveSSLSocketFactory": re.compile(r"NaiveSSLSocketFactory|NoCheckTrustManager|FakeTrustManager", re.IGNORECASE),
    "OkHttp HostnameVerifier(true)": re.compile(r"hostnameVerifier\(.*?\(.*?\$\d+;->.*?verify"),
}
# Evidence that a TLS-bypass primitive is ACTUALLY WIRED INTO the network stack,
# not merely defined/present. "presence != usage": an unused TrustAll class (or
# one only referenced inside a 3rd-party SDK) is not an exploitable bypass.
USAGE_MARKERS = (
    "setSSLSocketFactory", "setHostnameVerifier", "setDefaultHostnameVerifier",
    "setDefaultSSLSocketFactory", "sslSocketFactory", "hostnameVerifier",
    "init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;",
    "Ljavax/net/ssl/SSLContext;->init",
    "Ljavax/net/ssl/HttpsURLConnection;->setSSLSocketFactory",
    "Ljavax/net/ssl/HttpsURLConnection;->setHostnameVerifier",
)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["cert_validation_bypass_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["cert_validation_bypass_audit_error"] = str(e)
        return

    bypass_hits = {}        # all matches (label -> filenames), for intel
    app_bypass_hits = {}    # matches in APP code only (excludes lib/test paths)
    usage_seen = False      # any file actually wires a SocketFactory/HostnameVerifier
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        try:
            rel = str(p.relative_to(unpacked))
        except ValueError:
            rel = p.name
        app_code = is_app_code_path(rel)
        if not is_test_path(rel) and any(mk in txt for mk in USAGE_MARKERS):
            usage_seen = True
        for label, regex in BYPASS_PATTERNS.items():
            if regex.search(txt):
                bypass_hits.setdefault(label, [])
                if p.name not in bypass_hits[label] and len(bypass_hits[label]) < 10:
                    bypass_hits[label].append(p.name)
                if app_code:
                    app_bypass_hits.setdefault(label, [])
                    if p.name not in app_bypass_hits[label] and len(app_bypass_hits[label]) < 10:
                        app_bypass_hits[label].append(p.name)

    ctx.state["cert_validation_bypass_hits"] = bypass_hits
    ctx.state["cert_validation_bypass_app_hits"] = app_bypass_hits
    # A bypass is only graded CRITICAL when it's in app code AND the app actually
    # wires a custom SSLSocketFactory/HostnameVerifier somewhere. Definitions that
    # are never instantiated/used (or only present inside SDKs) -> INFO.
    ctx.state["cert_validation_bypass_used"] = bool(usage_seen)
    ctx.state["files_scanned"] = files_scanned
    ctx.state["cert_validation_bypass_audit_total"] = len(bypass_hits)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Cert-validation bypass patterns", "cert_validation_bypass_hits"),
    ("Bypass patterns in app code", "cert_validation_bypass_app_hits"),
    ("Custom SSL factory/verifier wired", "cert_validation_bypass_used"),
]


@router.post("/api/mobile_crypto/cert_validation_bypass_audit")
async def mobile_crypto_cert_validation_bypass_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="cert_validation_bypass_audit",
        gather_func=gather,
        finding_rules=CERT_VALIDATION_BYPASS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
