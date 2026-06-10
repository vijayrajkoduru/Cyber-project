"""request_forgery_origin — DNS rebinding + Origin header SSRF.

Tests two related attack classes:
  (1) Origin header reflected into back-end requests (Server-Side Request
      Forgery via Origin) — some apps log/echo Origin without sanitization
      into internal services.
  (2) DNS rebinding detection: server checks Host header at TLS but not
      at HTTP layer, allowing post-TLS Host change → IP-based ACL bypass.

Tests Host header switch + bogus Origin reflection patterns.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

EVIL_HOSTS = [
    "internal-admin.local",
    "169.254.169.254",  # AWS metadata service IP
    "metadata.google.internal",  # GCP metadata
    "127.0.0.1",
    "[::1]",
]


@router.post("/api/webapp/scan/request_forgery_origin")
@vl_turbo()
@vl_verify()
def scan_request_forgery_origin(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    # Baseline
    r0 = safe_request("GET", base + "/",
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)
    if r0 is None:
        return standard_response(
            tool="request_forgery_origin", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No baseline response")

    baseline_len = len(r0.content) if r0.content else 0
    baseline_status = r0.status_code

    findings = []
    accepted_evil = []
    reflected_origin = []

    for evil in EVIL_HOSTS:
        # Test 1: Host header attack
        r1 = safe_request("GET", base + "/",
            headers={"Host": evil, "User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r1 is not None:
            # If status differs from baseline AND server didn't reject (400/421)
            if r1.status_code not in (400, 404, 421) and r1.status_code != baseline_status:
                # Could be vhost routing — only flag if response markedly different
                if abs((len(r1.content) if r1.content else 0) - baseline_len) > 500:
                    accepted_evil.append({"host": evil, "status": r1.status_code,
                                            "size_delta": len(r1.content or b"") - baseline_len})

        # Test 2: Origin header reflection (XSS / SSRF via logging vector)
        r2 = safe_request("GET", base + "/",
            headers={"Origin": f"https://{evil}", "User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r2 is not None:
            body = (r2.text or "")[:20000]
            if evil in body or f"https://{evil}" in body:
                reflected_origin.append({"origin": f"https://{evil}",
                                           "status": r2.status_code})

    if accepted_evil:
        findings.append(wrap_finding(
            f"Host-header injection — {len(accepted_evil)} evil-host(s) returned non-baseline response",
            "MEDIUM", cvss="5.3", cwe="CWE-444", owasp="A05:2021",
            remediation="Configure web server to validate Host header against an "
                        "allow-list. nginx: 'if ($host !~* ^(your-domain\\.com)$) "
                        "{ return 421; }'. Apache: <Directory> + Require host. "
                        "Most vhost-routing setups need this to prevent DNS "
                        "rebinding + virtual-host confusion attacks.",
            evidence_marker=" | ".join(
                f"Host: {e['host']} → HTTP {e['status']} (delta {e['size_delta']}B)"
                for e in accepted_evil[:5]
            )))

    if reflected_origin:
        findings.append(wrap_finding(
            f"Origin header REFLECTED in body — XSS / SSRF-by-logging risk",
            "MEDIUM", cvss="5.3", cwe="CWE-79", owasp="A03:2021",
            remediation="Avoid logging or reflecting unsanitized Origin/Referer "
                        "headers. If you use them for CORS / CSRF protection, "
                        "compare against allow-list — don't echo. Logging "
                        "frameworks like Splunk / ELK have parser bugs triggered "
                        "by attacker-controlled header content.",
            evidence_marker=" | ".join(
                f"Origin: {e['origin']} reflected (HTTP {e['status']})"
                for e in reflected_origin[:5]
            )))

    if not findings:
        findings.append(wrap_finding(
            "Host + Origin header injection probes rejected / not reflected",
            "POSITIVE", cwe="CWE-444",
            remediation="Maintain. Continue Host-header allow-listing at server config.",
            evidence_marker=f"tested {len(EVIL_HOSTS)} evil hosts × 2 header attacks each"))

    return standard_response(
        tool="request_forgery_origin", target=req.target, findings=findings,
        tests_performed=1 + 2 * len(EVIL_HOSTS),
        vulnerable=bool(accepted_evil or reflected_origin),
        tests_summary=f"accepted_evil_host: {len(accepted_evil)}, "
                       f"reflected_origin: {len(reflected_origin)}",
        raw_data={"baseline_status": baseline_status,
                   "baseline_len": baseline_len,
                   "accepted_evil": accepted_evil,
                   "reflected_origin": reflected_origin})


def register(app):
    app.include_router(router)
