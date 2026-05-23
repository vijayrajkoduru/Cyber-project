"""Clickjacking — X-Frame-Options + CSP frame-ancestors check."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()

@router.post("/api/scan/clickjacking")
def scan_clickjacking(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_get(url, req=req, allow_redirects=True)
    if r is None:
        return standard_response(tool="clickjacking", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}")
    h = {k.lower(): v for k, v in r.headers.items()}
    xfo = h.get("x-frame-options", "")
    csp = h.get("content-security-policy", "") or ""
    has_fa = "frame-ancestors" in csp.lower()
    findings = []
    if not xfo and not has_fa:
        findings.append(wrap_finding(
            "No X-Frame-Options and no CSP frame-ancestors — clickjacking possible",
            "MEDIUM", cvss="6.1", cwe="CWE-1021", owasp="A05:2021",
            remediation="Add 'X-Frame-Options: DENY' OR 'frame-ancestors none' to CSP.",
            evidence_marker="neither X-Frame-Options nor CSP frame-ancestors present"))
    return standard_response(tool="clickjacking", target=req.target,
        findings=findings, tests_performed=1,
        tests_summary="Frame-embedding protection check",
        raw_data={"clickjacking": {"x_frame_options": xfo, "csp_frame_ancestors": has_fa}})
def register(app): app.include_router(router)
