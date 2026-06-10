"""trace_method_enabled — TRACE HTTP method = Cross-Site Tracing (XST) vector.

TRACE echoes the request back including cookies/auth headers. Combined
with an XSS, attacker can use XMLHttpRequest TRACE → read HttpOnly
cookies that JS normally can't access.

Modern browsers block JS-initiated TRACE, but legacy IE / curl-via-proxy
still works. Best practice: disable at edge.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()


@router.post("/api/webapp/scan/trace_method_enabled")
@vl_turbo()
@vl_verify()
def scan_trace_method_enabled(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target).rstrip("/")
    r = safe_request("TRACE", url + "/",
        headers={"User-Agent": "VulnusLab/1.0",
                  "X-Vulnuslab-Test-Header": "echo-this-back"},
        req=req, timeout=8, allow_redirects=False)
    if r is None:
        return standard_response(
            tool="trace_method_enabled", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No response to TRACE")

    body = (r.text or "")[:5000]

    findings = []
    if r.status_code == 200 and "X-Vulnuslab-Test-Header" in body:
        findings.append(wrap_finding(
            "TRACE method ENABLED — Cross-Site Tracing (XST) vector",
            "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A05:2021",
            remediation="Disable TRACE method at the web server: "
                        "Apache: 'TraceEnable Off'. "
                        "nginx: doesn't speak TRACE by default. "
                        "IIS: <verbs allowUnlisted='false'><add verb='TRACE' allowed='false' /></verbs> "
                        "in web.config. TRACE serves no production purpose.",
            evidence_marker=f"TRACE / → HTTP {r.status_code}, request headers echoed: "
                              f"X-Vulnuslab-Test-Header found in body"))
    elif r.status_code in (405, 501):
        findings.append(wrap_finding(
            f"TRACE method disabled (HTTP {r.status_code} Method Not Allowed)",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. TRACE is rarely used; keeping it disabled is "
                        "correct.",
            evidence_marker=f"TRACE / → HTTP {r.status_code}"))
    elif r.status_code == 200:
        # TRACE returned 200 but didn't echo our header — maybe load balancer responded
        findings.append(wrap_finding(
            "TRACE returned 200 but didn't echo headers (proxy intercepted)",
            "INFO", cwe="CWE-200",
            remediation="Verify back-end origin rejects TRACE too. Front-end "
                        "proxy may be hiding back-end TRACE behavior.",
            evidence_marker=f"TRACE / → HTTP 200, no echo (body: {body[:100]})"))
    else:
        findings.append(wrap_finding(
            f"TRACE not enabled (HTTP {r.status_code})",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain.",
            evidence_marker=f"TRACE / → HTTP {r.status_code}"))

    return standard_response(
        tool="trace_method_enabled", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=any(f.get("severity") == "MEDIUM" for f in findings),
        tests_summary=f"TRACE → HTTP {r.status_code}",
        raw_data={"trace_status": r.status_code,
                   "body_snippet": body[:300]})


def register(app):
    app.include_router(router)
