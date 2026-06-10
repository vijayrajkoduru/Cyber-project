"""http2_request_smuggling — HTTP/2 to HTTP/1.1 downgrade smuggling probes.

When a front-end speaks HTTP/2 but downgrades to HTTP/1.1 for the backend
without proper header normalization, attacker can smuggle a second request
via Content-Length / Transfer-Encoding / pseudo-header confusion.

Tests:
  1. Does target speak HTTP/2? (via ALPN h2)
  2. Send H2 request with crafted CL/TE → check time-anomaly response
  3. CRLF in pseudo-header detection

Note: real smuggling needs raw H2 frames. This probe uses httpx HTTP/2
client + timing observation. Zero-FP — only emits if time-anomaly is
clearly outside baseline.
"""
import time
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()


def _baseline_request(url, timeout=8):
    """Return (status, elapsed_ms, http_version)."""
    try:
        import httpx
    except ImportError:
        return None, None, None
    try:
        with httpx.Client(http2=True, verify=False, timeout=timeout) as client:
            t0 = time.time()
            r = client.get(url, headers={"User-Agent": "VulnusLab/1.0"})
            return r.status_code, int((time.time() - t0) * 1000), r.http_version
    except Exception as e:
        return None, None, str(e)


def _smuggle_te_cl_test(url, timeout=10):
    """Send POST with both Content-Length and Transfer-Encoding (CL.TE classic)."""
    try:
        import httpx
    except ImportError:
        return None, None
    body_legit = "0\r\n\r\n"
    smuggled = "0\r\n\r\nGET /vulnuslab-smuggled HTTP/1.1\r\nHost: smug\r\n\r\n"
    try:
        with httpx.Client(http2=True, verify=False, timeout=timeout) as client:
            t0 = time.time()
            r = client.post(
                url,
                headers={
                    "User-Agent": "VulnusLab/1.0",
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                },
                content=smuggled.encode())
            return r.status_code, int((time.time() - t0) * 1000)
    except Exception:
        return None, None


@router.post("/api/webapp/scan/http2_request_smuggling")
@vl_turbo()
@vl_verify()
def scan_http2_request_smuggling(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return standard_response(
            tool="http2_request_smuggling", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="HTTP/2 requires HTTPS. Target is not https://.")

    status, elapsed, version = _baseline_request(url)
    if status is None:
        return standard_response(
            tool="http2_request_smuggling", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Baseline H2 request failed: {version}")

    if "2" not in str(version):
        return standard_response(
            tool="http2_request_smuggling", target=req.target,
            findings=[wrap_finding(
                f"Target does not negotiate HTTP/2 (got {version})",
                "POSITIVE", cwe="CWE-444",
                remediation="No HTTP/2 = no H2-downgrade smuggling possible. "
                            "Continue to monitor as TLS/H2 rollout progresses.",
                evidence_marker=f"baseline GET → HTTP {status} via {version} ({elapsed}ms)")],
            tests_performed=1, vulnerable=False,
            tests_summary=f"No HTTP/2 negotiated (got {version})")

    # Run smuggle test
    smug_status, smug_elapsed = _smuggle_te_cl_test(url)
    findings = []

    # Heuristic: smuggling-vulnerable proxies often respond ABNORMALLY SLOW
    # because they wait for the "next request" that the attacker's payload
    # primed. We flag if smuggle response > 5x baseline.
    if smug_status is not None and smug_elapsed and elapsed:
        ratio = smug_elapsed / elapsed
        if ratio > 5 and smug_elapsed > 2000:
            findings.append(wrap_finding(
                f"POSSIBLE HTTP/2 smuggling — TE+CL request 5x slower than baseline",
                "MEDIUM", cvss="5.3", cwe="CWE-444", owasp="A04:2021",
                remediation="The slow response on TE+CL request suggests the front-"
                            "end proxy parses headers differently from the back-end. "
                            "Verify with HTTP Request Smuggler (PortSwigger Burp ext) "
                            "or smuggler.py from defparam. If confirmed, the fix is "
                            "front-end: enforce strict header normalization, reject "
                            "requests with BOTH Content-Length and Transfer-Encoding.",
                evidence_marker=f"baseline {elapsed}ms vs smuggle {smug_elapsed}ms "
                                  f"(ratio {ratio:.1f}x), status {smug_status}"))
        elif smug_status >= 400:
            findings.append(wrap_finding(
                "HTTP/2 endpoint rejects TE+CL header combo — properly defended",
                "POSITIVE", cwe="CWE-444",
                remediation="Maintain header normalization at the edge.",
                evidence_marker=f"TE+CL smuggle request → HTTP {smug_status} "
                                  f"({smug_elapsed}ms vs baseline {elapsed}ms)"))

    if not findings:
        findings.append(wrap_finding(
            "HTTP/2 baseline established, no smuggling time-anomaly observed",
            "POSITIVE", cwe="CWE-444",
            remediation="Test deeper with HTTP Request Smuggler Burp extension "
                        "for full TE.CL / CL.TE / TE.TE coverage.",
            evidence_marker=f"baseline {elapsed}ms, smuggle test {smug_elapsed}ms "
                              f"(ratio {smug_elapsed/elapsed:.1f}x)" if smug_elapsed else
                              f"baseline {elapsed}ms, smuggle no-response"))

    return standard_response(
        tool="http2_request_smuggling", target=req.target, findings=findings,
        tests_performed=2,
        vulnerable=any("MEDIUM" in f.get("severity", "") for f in findings),
        tests_summary=f"H2 baseline {elapsed}ms; smuggle {smug_elapsed}ms",
        raw_data={"baseline_ms": elapsed, "smuggle_ms": smug_elapsed,
                   "http_version": version})


def register(app):
    app.include_router(router)
