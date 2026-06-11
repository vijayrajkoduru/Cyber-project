"""mtls_audit — Mutual TLS (client-cert) auth detection on sensitive endpoints.

Some apps require mTLS for admin/internal endpoints. Probe: connect
WITHOUT client cert → if server returns SSL handshake failure (or HTTP
403 with cert-required message), mTLS is active. Otherwise, the
endpoint relies on application-layer auth alone.

For high-value targets (admin /, financial APIs), absence of mTLS is a
defense-in-depth gap, not a vuln per se.
"""
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

SENSITIVE_PATHS = [
    "/admin", "/admin/", "/admin/login", "/api/admin",
    "/internal", "/management", "/actuator", "/debug",
]


def _check_mtls_required(host, port, path="/", timeout=8):
    """Try TLS handshake without a client cert. Return (mtls_required, evidence)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Do NOT load a client cert — that's the point of the test
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=host)
        except ssl.SSLError as e:
            sock.close()
            err = str(e).lower()
            if "certificate" in err or "no shared cipher" in err or "alert" in err:
                return True, f"TLS handshake rejected: {e}"
            return False, f"TLS handshake error (non-mTLS): {e}"
        # Handshake succeeded. Send HTTP request.
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: VulnusLab/1.0\r\nConnection: close\r\n\r\n"
        ssock.sendall(req.encode())
        resp = b""
        try:
            while len(resp) < 8192:
                chunk = ssock.recv(2048)
                if not chunk: break
                resp += chunk
        except Exception:
            pass
        ssock.close()
        # Look for mTLS-required indicators
        header_line = resp.split(b"\r\n", 1)[0].decode(errors="ignore")
        body = resp.lower()
        mtls_hints = [b"client certificate", b"ssl_client_cert", b"mtls",
                       b"mutual tls", b"x509 cert", b"requires client cert"]
        if any(h in body for h in mtls_hints):
            return True, f"HTTP body indicates mTLS required: {header_line}"
        return False, f"Plain TLS (no client cert needed): {header_line}"
    except Exception as e:
        return False, f"connect error: {e}"


@router.post("/api/webapp/scan/mtls_audit")
@vl_turbo()
@vl_verify()
def scan_mtls_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return standard_response(
            tool="mtls_audit", target=req.target,
            findings=[wrap_finding(
                "Target is HTTP — mTLS not applicable",
                "INFO", cwe="CWE-295",
                remediation="mTLS requires TLS. Add HTTPS first.",
                evidence_marker=f"scheme: {parsed.scheme}")],
            tests_performed=0, vulnerable=False,
            tests_summary="Not HTTPS")

    host = parsed.hostname
    port = parsed.port or 443

    # Test 1: root TLS without client cert
    main_mtls, main_evidence = _check_mtls_required(host, port, "/")

    # Test 2: sensitive paths via standard HTTPS GET
    sensitive_findings = []
    accessible_sensitive = []

    def _path_probe(path):
        r = safe_request("GET", f"https://{host}:{port}{path}",
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r is None: return None
        if r.status_code != 404:
            return {"path": path, "status": r.status_code}
        return None

    # VL-TURBO deep: parallelize 8 sensitive-path probes via pool(8).
    # Was ~64s sequential, now ~8s parallel.
    with ThreadPoolExecutor(max_workers=min(8, len(SENSITIVE_PATHS))) as pool:
        for result in pool.map(_path_probe, SENSITIVE_PATHS, timeout=21):
            if result is not None:
                accessible_sensitive.append(result)

    findings = []
    if main_mtls:
        findings.append(wrap_finding(
            "mTLS enforced at root TLS layer — strong defense",
            "POSITIVE", cwe="CWE-295",
            remediation="Maintain. Verify cert pinning + CRL/OCSP stapling.",
            evidence_marker=main_evidence))
    elif accessible_sensitive:
        findings.append(wrap_finding(
            f"Sensitive endpoint(s) ({len(accessible_sensitive)}) accessible without mTLS",
            "INFO", cwe="CWE-295",
            remediation="For high-value endpoints (/admin, /actuator, /debug), "
                        "consider mTLS as defense-in-depth on top of "
                        "application-layer auth. Configure at edge (nginx "
                        "ssl_verify_client on; or AWS ALB mTLS). Issue client "
                        "certs to authorized operators via internal CA + revoke "
                        "on offboarding.",
            evidence_marker=" | ".join(
                f"{s['path']}: HTTP {s['status']}" for s in accessible_sensitive[:5]
            )))
    else:
        findings.append(wrap_finding(
            "No mTLS enforcement, no sensitive paths found to flag",
            "POSITIVE", cwe="CWE-295",
            remediation="Standard public-web TLS. mTLS not needed for typical "
                        "user-facing app — only for admin/B2B/IoT endpoints.",
            evidence_marker=main_evidence))

    return standard_response(
        tool="mtls_audit", target=req.target, findings=findings,
        tests_performed=1 + len(SENSITIVE_PATHS),
        vulnerable=False,
        tests_summary=f"mTLS root: {main_mtls}, sensitive paths unprot: {len(accessible_sensitive)}",
        raw_data={"mtls_at_root": main_mtls,
                   "main_evidence": main_evidence,
                   "sensitive_accessible": accessible_sensitive})


def register(app):
    app.include_router(router)
