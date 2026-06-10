"""h2c_smuggling — HTTP/2 cleartext smuggling via Upgrade header.

If front-end proxy supports HTTP/1.1 Upgrade: h2c, it may forward the
connection raw to backend. Attacker uses this to smuggle HTTP/2 frames
past front-end auth → access internal endpoints.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()


@router.post("/api/webapp/scan/h2c_smuggling")
@vl_turbo()
def scan_h2c_smuggling(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    # Probe with Upgrade: h2c, HTTP2-Settings: <base64-encoded SETTINGS frame>
    r = safe_request("GET", base + "/",
        headers={"User-Agent": "VulnusLab/1.0",
                  "Connection": "Upgrade, HTTP2-Settings",
                  "Upgrade": "h2c",
                  "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA"},
        req=req, timeout=8, allow_redirects=False)
    findings = []
    if r is None:
        return standard_response(
            tool="h2c_smuggling", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="no response")
    # 101 Switching Protocols = h2c upgrade accepted
    if r.status_code == 101:
        upgrade_hdr = (r.headers.get("upgrade") or "").lower()
        if "h2c" in upgrade_hdr:
            findings.append(wrap_finding(
                "HTTP/2 cleartext (h2c) UPGRADE accepted — smuggling vector",
                "HIGH", cvss="7.5", cwe="CWE-444", owasp="A05:2021",
                remediation="Disable h2c at the front-end proxy. Most front-ends "
                            "shouldn't accept Upgrade: h2c from clients (it's a "
                            "server-side decision, not client-driven). nginx: "
                            "explicitly drop Upgrade: h2c. CloudFlare / AWS ALB "
                            "block by default but custom proxies may not.",
                evidence_marker=f"HTTP 101, Upgrade: {upgrade_hdr}"))
    if not findings:
        findings.append(wrap_finding(
            f"h2c upgrade rejected (HTTP {r.status_code})",
            "POSITIVE", cwe="CWE-444",
            remediation="Maintain.",
            evidence_marker=f"GET / with Upgrade: h2c → HTTP {r.status_code}"))
    return standard_response(
        tool="h2c_smuggling", target=req.target, findings=findings,
        tests_performed=1, vulnerable=any(f.get("severity") == "HIGH" for f in findings),
        tests_summary=f"h2c probe → HTTP {r.status_code}",
        raw_data={"status": r.status_code})


def register(app): app.include_router(router)
