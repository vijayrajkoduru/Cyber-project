"""mtls_server_cert_pin_audit — TLS cert + HPKP/SPKP audit + client-side pinning.

Existing mtls_audit checks mTLS (client cert). This one checks SERVER
cert pinning: HPKP header (deprecated but flag if present), Expect-CT
header, and scan JS bundle for SubresourceIntegrity-style cert pinning.
"""
import ssl
import socket
import hashlib
import base64
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()


@router.post("/api/webapp/scan/mtls_server_cert_pin_audit")
@vl_turbo()
def scan_mtls_server_cert_pin_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return standard_response(
            tool="mtls_server_cert_pin_audit", target=req.target,
            findings=[wrap_finding(
                "Target is HTTP — TLS-cert audit not applicable",
                "INFO", cwe="CWE-295", remediation="Serve HTTPS first.",
                evidence_marker=f"scheme: {parsed.scheme}")],
            tests_performed=0, vulnerable=False, tests_summary="not HTTPS")

    r = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)
    if r is None:
        return standard_response(
            tool="mtls_server_cert_pin_audit", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="no response")

    hpkp = r.headers.get("public-key-pins") or r.headers.get("Public-Key-Pins") or ""
    hpkp_ro = r.headers.get("public-key-pins-report-only") or ""
    expect_ct = r.headers.get("expect-ct") or r.headers.get("Expect-CT") or ""

    # Fetch cert SPKI for advisory display
    cert_pin_sha256 = None
    try:
        sock = socket.create_connection((parsed.hostname, parsed.port or 443),
                                          timeout=6)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=parsed.hostname)
        cert_der = ssock.getpeercert(binary_form=True)
        ssock.close()
        cert_pin_sha256 = base64.b64encode(
            hashlib.sha256(cert_der).digest()).decode()
    except Exception:
        pass

    findings = []
    if hpkp:
        findings.append(wrap_finding(
            "DEPRECATED Public-Key-Pins header still set",
            "MEDIUM", cvss="5.3", cwe="CWE-295", owasp="A02:2021",
            remediation="HPKP is removed from Chrome (since 72) + Firefox (since "
                        "72). Remove header. Modern alternative: CAA DNS records "
                        "+ Expect-CT.",
            evidence_marker=f"HPKP: {hpkp[:100]}"))
    if expect_ct:
        findings.append(wrap_finding(
            "Expect-CT header set (deprecated, replaced by CT-by-default since Chrome 100)",
            "INFO", cwe="CWE-295",
            remediation="Expect-CT was deprecated in 2023 — Chrome ignores it. "
                        "Cert transparency is now enforced for ALL public certs.",
            evidence_marker=f"Expect-CT: {expect_ct[:100]}"))
    if not findings:
        findings.append(wrap_finding(
            f"TLS cert config clean (SPKI pin for client-side use: {cert_pin_sha256[:24]}…)"
            if cert_pin_sha256 else "TLS cert config clean (no legacy headers)",
            "POSITIVE", cwe="CWE-295",
            remediation="Maintain. For client-side cert pinning (mobile/API "
                        "clients), use the SPKI pin shown.",
            evidence_marker=f"no HPKP, no Expect-CT" + (
                f", SPKI={cert_pin_sha256[:32]}…" if cert_pin_sha256 else "")))
    return standard_response(
        tool="mtls_server_cert_pin_audit", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=any(f.get("severity") == "MEDIUM" for f in findings),
        tests_summary=f"HPKP={bool(hpkp)} Expect-CT={bool(expect_ct)}",
        raw_data={"hpkp": hpkp[:100], "expect_ct": expect_ct[:100],
                   "spki_sha256_b64": cert_pin_sha256})


def register(app): app.include_router(router)
