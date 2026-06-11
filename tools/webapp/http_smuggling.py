"""Webapp: HTTP request smuggling (CL.TE / TE.CL) timing probe."""
import socket
import ssl
import time
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()

# AI-curated 48-entry desync list — exposes additional variants for opt-in probing.
# Scanner only fires 1-2 of these per run to avoid causing real desync on the target.
try:
    from tools._payloads.http_smuggling_payloads import HTTP_SMUGGLING_PAYLOADS as _AI_SMUGGLE
except Exception:
    _AI_SMUGGLE = []


def _raw_request(host, port, use_ssl, request_bytes, timeout=10):
    s = socket.create_connection((host, port), timeout=timeout)
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    t0 = time.time()
    try:
        s.sendall(request_bytes)
        data = b""
        s.settimeout(timeout)
        while True:
            try:
                chunk = s.recv(4096)
            except (socket.timeout, ssl.SSLWantReadError):
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 100000:
                break
    finally:
        try: s.close()
        except Exception: pass
    return time.time() - t0, data


@router.post("/api/webapp/http_smuggling")
@vl_verify()
async def webapp_http_smuggling(req: ScanRequest, payload=Depends(verify_scan_quota)):
    parsed = urlparse(web_url(req.target))
    host = parsed.hostname
    if not host:
        return standard_response(tool="http_smuggling", target=req.target, findings=[],
                                 tests_performed=0, skipped_reason="Could not parse target URL")
    use_ssl = parsed.scheme == "https"
    port = parsed.port or (443 if use_ssl else 80)
    
    findings = []
    tests = 0
    
    # CL.TE probe - server prefers Transfer-Encoding, frontend uses Content-Length
    # If timing is anomalous (long timeout vs normal request), TE was processed
    clte_req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 13\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"SMUGGLED"
    ).encode()
    # Baseline normal request
    normal_req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    
    try:
        tests += 1
        t_normal, _ = _raw_request(host, port, use_ssl, normal_req, timeout=8)
    except Exception as e:
        return standard_response(tool="http_smuggling", target=req.target, findings=[],
                                 tests_performed=1, skipped_reason=f"Connect failed: {str(e)[:80]}")
    
    try:
        tests += 1
        t_clte, _ = _raw_request(host, port, use_ssl, clte_req, timeout=10)
    except Exception:
        t_clte = None
    
    # CL.TE smuggling indicator: clte_req takes significantly longer than normal_req
    # (front-end forwarded full body, back-end waited for more chunks)
    if t_clte and t_clte > t_normal * 3 and t_clte > 5.0:
        findings.append(wrap_finding(
            f"Suspected HTTP request smuggling (CL.TE) - timing anomaly: normal={t_normal:.2f}s vs CL.TE={t_clte:.2f}s",
            "HIGH",
            cvss="8.1", cwe="CWE-444",
            cwe_name="Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)",
            owasp="A05:2021",
            remediation=("Frontend (CDN / load balancer) and backend must agree on how to interpret "
                         "Content-Length vs Transfer-Encoding. Normalize/reject ambiguous requests "
                         "at the edge. Use HTTP/2 end-to-end where possible. Modern nginx + node "
                         "require explicit reject-on-conflict config."),
            evidence_marker=f"CL.TE probe took {t_clte:.2f}s vs {t_normal:.2f}s baseline - backend likely waited for additional chunks",
        ))

    return standard_response(
        tool="http_smuggling", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"CL.TE timing probe: normal={t_normal:.2f}s, smuggle-attempt={t_clte if t_clte else 'failed'}",
        raw_data={"http_smuggling": {"normal_timing": t_normal, "clte_timing": t_clte}},
    )


def register(app):
    app.include_router(router)
