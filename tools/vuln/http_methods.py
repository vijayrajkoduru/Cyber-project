"""HTTP methods enumeration.

Active probing: discovers methods via OPTIONS, then sends individual
TRACE/PUT/DELETE/PATCH/CONNECT/TRACK requests. A method is reported
ALLOWED only when the server returns anything other than 405 or 501.

Severity model:
  HIGH    — TRACE enabled (Cross-Site Tracing / cookie theft)
  HIGH    — PUT/DELETE allowed (unauthorized file write/delete)
  MEDIUM  — PATCH, CONNECT, TRACK
"""
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_request, wrap_finding, standard_response,
)

router = APIRouter()


ACTIVE_PROBES = ["TRACE", "PUT", "DELETE", "PATCH", "CONNECT", "TRACK"]

METHOD_RISK = {
    "TRACE":   ("HIGH",   "CWE-200",
                "Disable TRACE (TraceEnable off in Apache). TRACE enables "
                "Cross-Site Tracing attacks that can steal cookies."),
    "TRACK":   ("MEDIUM", "CWE-200",
                "Block the TRACK method explicitly; some servers allow it "
                "as a TRACE bypass."),
    "PUT":     ("HIGH",   "CWE-650",
                "Disable PUT or require strong auth + authorization. "
                "PUT can allow unauthorized file upload."),
    "DELETE":  ("HIGH",   "CWE-650",
                "Disable DELETE or require strong auth + authorization."),
    "PATCH":   ("MEDIUM", "CWE-650",
                "Restrict PATCH to authorized endpoints with proper auth."),
    "CONNECT": ("MEDIUM", "CWE-441",
                "Disable CONNECT. It can turn the server into an open proxy."),
}


@router.post("/api/scan/http_methods")
async def scan_http_methods(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    tests = 0
    allowed = set()
    probed = {}

    # Step 1 — OPTIONS discovery
    tests += 1
    r_opt = safe_request("OPTIONS", url, req=req, allow_redirects=False)
    allow_header = ""
    if r_opt is not None:
        allow_header = r_opt.headers.get("Allow", "")
        for m in [x.strip().upper() for x in allow_header.split(",") if x.strip()]:
            allowed.add(m)

    # Step 2 — Active probe each risky method
    for method in ACTIVE_PROBES:
        tests += 1
        r = safe_request(method, url, req=req, allow_redirects=False)
        if r is None:
            probed[method] = "no response"
            continue
        probed[method] = r.status_code
        if r.status_code in (200, 201, 202, 204, 207, 301, 302, 401, 403):
            allowed.add(method)

    # Step 3 — Emit findings
    for method in ACTIVE_PROBES:
        if method in allowed:
            sev, cwe, remediation = METHOD_RISK[method]
            findings.append(wrap_finding(
                f"HTTP {method} method enabled",
                sev, cwe=cwe,
                evidence_marker=f"{method} {url} -> status={probed.get(method)}",
                remediation=remediation,
                tests_performed=1,
            ))

    return standard_response(
        tool="http_methods", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"OPTIONS + {len(ACTIVE_PROBES)} active method probes",
        raw_data={
            "http_methods": {
                "options_allow_header": allow_header,
                "probed_status": probed,
                "allowed_methods": sorted(allowed),
            }
        },
    )


def register(app):
    app.include_router(router)
