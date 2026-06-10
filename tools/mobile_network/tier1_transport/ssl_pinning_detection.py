"""ssl_pinning_detection (§5 #56-#59 static side) — identify WHICH pinning
library + technique the app uses. Output tells the pentester what to
bypass: OkHttp CertificatePinner vs TrustKit vs native pinning vs
TrustManager subclass. Includes pin SHA-256 extraction when present."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.ssl_pinning_detection_findings import SSL_PINNING_DETECTION_FINDING_RULES

router = APIRouter()

PINNING_MARKERS = {
    "OkHttp CertificatePinner":  ["okhttp3/CertificatePinner", "CertificatePinner$Builder"],
    "Square Conscrypt Pinning":  ["Lcom/squareup/okhttp3/CertificatePinner"],
    "TrustKit":                  ["com/datatheorem/android/trustkit", "TrustKit"],
    "AppMattus CertificateTransparency": ["com/appmattus/certificatetransparency"],
    "Cronet QUIC pinning":       ["org/chromium/net/PublicKeyPins"],
    "Native pinning library":    ["NativePinningTrustManager", "PinningManager"],
    "Custom TrustManager subclass": ["X509TrustManager", "checkServerTrusted"],
    "Volley HurlStack pinning":  ["HurlStack", "Volley.*SSLSocketFactory"],
    "Cordova SSL pinning plugin": ["cordova-plugin-advanced-http"],
    "React-Native ssl-pinning":  ["RNFetchBlob", "react-native-ssl-pinning"],
}
PIN_SHA256_PATTERN = re.compile(r'"(sha256/[A-Za-z0-9+/=]{40,50})"')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ssl_pinning_detection_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["ssl_pinning_detection_error"] = str(e)
        return

    pinning_libs = {}
    extracted_pins = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for lib_name, markers in PINNING_MARKERS.items():
            for m in markers:
                if m in txt:
                    pinning_libs.setdefault(lib_name, [])
                    if p.name not in pinning_libs[lib_name] and len(pinning_libs[lib_name]) < 5:
                        pinning_libs[lib_name].append(p.name)
                    break
        for m in PIN_SHA256_PATTERN.finditer(txt):
            pin = m.group(1)
            if pin not in extracted_pins and len(extracted_pins) < 20:
                extracted_pins.append(pin)

    ctx.state["pinning_libraries"] = pinning_libs
    ctx.state["extracted_pins"] = extracted_pins
    ctx.state["files_scanned"] = files_scanned
    ctx.state["ssl_pinning_detection_total"] = len(pinning_libs)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("SSL pinning libraries detected", "pinning_libraries"),
    ("Extracted SHA-256 pins", "extracted_pins"),
]


@router.post("/api/mobile_network/ssl_pinning_detection")
async def mobile_network_ssl_pinning_detection(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ssl_pinning_detection",
        gather_func=gather,
        finding_rules=SSL_PINNING_DETECTION_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
