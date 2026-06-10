"""certificate_pinning_static — detect SSL/TLS pinning libraries in DEX.

Apps without certificate pinning are vulnerable to MitM via user-installed
root CAs (Burp/mitmproxy on rooted/jailbroken devices). Scan for:
- OkHttp CertificatePinner
- TrustKit (iOS + Android)
- Network Security Config <pin-set> (already covered by network_security_config_audit)
- Custom TrustManager / SSLContext

MASVS-NETWORK-2 / MSTG-NETWORK-3.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.certificate_pinning_static_findings import \
    CERTIFICATE_PINNING_STATIC_FINDING_RULES

router = APIRouter()

PIN_MARKERS = [
    (b"Lokhttp3/CertificatePinner",      "OkHttp CertificatePinner"),
    (b"CertificatePinner$Builder",       "OkHttp CertificatePinner builder"),
    (b"Lcom/datatheorem/android/trustkit","TrustKit"),
    (b"Lokhttp3/internal/tls/",           "OkHttp TLS internals"),
    (b"Ljavax/net/ssl/X509TrustManager", "X509TrustManager"),
    (b"sun/security/ssl",                  "Java security SSL"),
    # iOS-side
    (b"SSLPinningMode",                    "AFNetworking pinning"),
    (b"sslPinningMode",                    "AFNetworking pinning lowercase"),
    (b"SSLCertificateChainHelper",         "TrustKit iOS"),
]

# Insecure markers (red flags — found = BAD)
INSECURE_MARKERS = [
    (b"checkServerTrusted", "Stubbed checkServerTrusted (TrustManager bypass)"),
    (b"ALLOW_ALL_HOSTNAME_VERIFIER", "Allow-all hostname verifier"),
    (b"AllowAllHostnameVerifier",    "Allow-all hostname verifier"),
    (b"NoopHostnameVerifier",        "NoopHostnameVerifier (no validation)"),
    (b"trustAllSSL",                  "trustAllSSL helper"),
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["certificate_pinning_static_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["certificate_pinning_static_error"] = str(e); return

    pinning_found = []
    insecure_found = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali", ".so") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for marker, desc in PIN_MARKERS:
            if marker in data and desc not in [p["desc"] for p in pinning_found]:
                pinning_found.append({"desc": desc, "marker": marker.decode(errors="ignore")})
        for marker, desc in INSECURE_MARKERS:
            if marker in data and desc not in [p["desc"] for p in insecure_found]:
                insecure_found.append({"desc": desc, "marker": marker.decode(errors="ignore")})

    ctx.state["pinning_markers_found"] = pinning_found
    ctx.state["insecure_tls_markers"] = insecure_found
    ctx.state["certificate_pinning_static_total"] = len(pinning_found) + len(insecure_found) * 3
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} files")


INTEL_FIELDS = [
    ("Pinning markers",   "pinning_markers_found"),
    ("Insecure TLS markers","insecure_tls_markers"),
    ("Files scanned",     "files_scanned"),
]


@router.post("/api/mobile_static/certificate_pinning_static")
async def mobile_static_certificate_pinning_static(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="certificate_pinning_static",
        gather_func=gather,
        finding_rules=CERTIFICATE_PINNING_STATIC_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
