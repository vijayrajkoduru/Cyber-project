"""tls_version_audit (§4 #51) — detect insecure TLS configuration:
- TLSv1.0 / TLSv1.1 literals (both deprecated by PCI-DSS 2018+)
- minSdkVersion < 21 (forced to TLS 1.0/1.1)
- network_security_config trust-anchors set to user CA (MITM exposure)
- Allow ALL hostname verifier
- Custom SSLContext.getInstance("SSL") or "TLS" (defaults)."""
from __future__ import annotations
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.tls_version_audit_findings import TLS_VERSION_AUDIT_FINDING_RULES

router = APIRouter()

NS = {"a": "http://schemas.android.com/apk/res/android"}
TLS_PATTERNS = {
    "TLSv1.0":              re.compile(r'"TLSv1\.0"|"TLSv1"'),
    "TLSv1.1":              re.compile(r'"TLSv1\.1"'),
    "SSLv2/SSLv3":          re.compile(r'"SSLv[23]"'),
    "Cipher.getInstance SSL only": re.compile(r'SSLContext.*getInstance\("SSL"\)'),
    "ALLOW_ALL_HOSTNAME_VERIFIER": re.compile(r"ALLOW_ALL_HOSTNAME_VERIFIER"),
    "HostnameVerifier returns true": re.compile(r'\.method.*verify\([^)]*\).*?\n.*?const/4 v\d+, 0x1', re.DOTALL),
}
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["tls_version_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["tls_version_audit_error"] = str(e)
        return

    # Manifest minSdkVersion check
    min_sdk = None
    manifest = unpacked / "AndroidManifest.xml"
    if manifest.is_file():
        try:
            root = ET.parse(str(manifest)).getroot()
            usdk = root.find("uses-sdk")
            if usdk is not None:
                min_sdk = usdk.get(f"{{{NS['a']}}}minSdkVersion")
        except ET.ParseError:
            pass

    findings_by_marker = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for label, regex in TLS_PATTERNS.items():
            if regex.search(txt):
                findings_by_marker.setdefault(label, [])
                if p.name not in findings_by_marker[label] and len(findings_by_marker[label]) < 10:
                    findings_by_marker[label].append(p.name)

    # network_security_config.xml — trust-anchors / user
    nsc_issues = []
    nsc_dir = unpacked / "res" / "xml"
    if nsc_dir.is_dir():
        for x in nsc_dir.glob("network_security_config*.xml"):
            try:
                txt = x.read_text(errors="ignore")
                if 'trust-anchors' in txt and ('user' in txt or '"user"' in txt):
                    nsc_issues.append(f"{x.name} — trusts user-added CAs")
                if 'cleartextTrafficPermitted="true"' in txt:
                    nsc_issues.append(f"{x.name} — cleartext permitted")
            except OSError:
                pass

    ctx.state["tls_marker_hits"] = findings_by_marker
    ctx.state["network_security_config_issues"] = nsc_issues
    ctx.state["min_sdk"] = min_sdk
    ctx.state["files_scanned"] = files_scanned
    ctx.state["tls_version_audit_total"] = (
        len(findings_by_marker) + len(nsc_issues) +
        (1 if min_sdk and min_sdk.isdigit() and int(min_sdk) < 21 else 0))
    ctx.source(f"manifest + {files_scanned} smali + nsc xml")


INTEL_FIELDS = [
    ("TLS markers in code", "tls_marker_hits"),
    ("network_security_config issues", "network_security_config_issues"),
    ("minSdkVersion", "min_sdk"),
]


@router.post("/api/mobile_crypto/tls_version_audit")
async def mobile_crypto_tls_version_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="tls_version_audit",
        gather_func=gather,
        finding_rules=TLS_VERSION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
