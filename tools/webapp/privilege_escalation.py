"""Webapp: Vertical privilege escalation via header / role manipulation."""
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()

_ADMIN_PATHS = ["/admin","/admin/users","/admin/dashboard","/admin/settings","/api/admin","/api/admin/users","/api/internal","/api/private"]
_AUTH_BYPASS_HEADERS = [
    {"X-User-Role": "admin"},
    {"X-Auth-Role": "admin"},
    {"X-Forwarded-User": "admin"},
    {"X-Original-User": "admin"},
    {"X-Custom-Auth": "admin"},
    {"X-Authenticated-User": "admin"},
]


@router.post("/api/webapp/privilege_escalation")
async def webapp_privilege_escalation(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    suspect = []
    
    for path in _ADMIN_PATHS:
        # Baseline: request without any custom headers
        tests += 1
        baseline = safe_get(base + path, req=req, allow_redirects=False, timeout=6)
        if baseline is None:
            continue
        # If baseline is already 200, this is a forced_browsing issue (separate scanner)
        if baseline.status_code in (200, 302):
            continue
        # Only proceed if baseline blocks access (401/403)
        if baseline.status_code not in (401, 403, 404):
            continue
        b_status = baseline.status_code
        # Try each auth-bypass header
        for hdr in _AUTH_BYPASS_HEADERS:
            tests += 1
            try:
                r = requests.get(base + path, headers={**hdr, "User-Agent":"VulnusLab/1.0"},
                                 timeout=6, allow_redirects=False, verify=False)
            except Exception:
                continue
            if r.status_code == 200 and len(r.content) > 200:
                hdr_name = list(hdr.keys())[0]
                suspect.append({"path": path, "header": hdr_name, "baseline_status": b_status, "bypass_status": 200})
                findings.append(wrap_finding(
                    f"Privilege escalation - {hdr_name} header bypasses access control on {path}",
                    "CRITICAL",
                    cvss="9.8", cwe="CWE-285",
                    cwe_name="Improper Authorization",
                    owasp="A01:2021",
                    remediation=("Never trust user-controllable headers for authorization. Derive the "
                                 "user's role from a server-validated session/JWT, not from request "
                                 "headers. If a reverse proxy injects auth headers, strip them at "
                                 "the proxy before passing to the application."),
                    evidence_marker=f"GET {path} baseline {b_status}; GET {path} with '{hdr_name}: admin' -> 200 ({len(r.content)} bytes)",
                ))
                break

    return standard_response(
        tool="privilege_escalation", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Tested {len(_ADMIN_PATHS)} admin paths against {len(_AUTH_BYPASS_HEADERS)} bypass headers",
        raw_data={"privilege_escalation": {"suspect": suspect}},
    )


def register(app):
    app.include_router(router)
