"""Clickjacking — X-Frame-Options + CSP frame-ancestors check.

VL-VERIFY: single-path scanner that audits the homepage's X-Frame-Options
header. The SPA homepage IS the real homepage under audit, so the canary
check is a context stamp only - no behavior change. The stamp surfaces
the SPA context in the report alongside the header finding.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.spa_canary import detect_spa_catchall_sync
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
router = APIRouter()

@router.post("/api/webapp/scan/clickjacking")
@vl_turbo()
@vl_verify()
def scan_clickjacking(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    spa = detect_spa_catchall_sync(url.rstrip("/"))
    r = safe_get(url, req=req, allow_redirects=True, timeout=10)
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
            severity="MEDIUM", cvss="6.1", cwe="CWE-1021", owasp="A05:2021",
            remediation="Add 'X-Frame-Options: DENY' OR 'frame-ancestors none' to CSP.",
            evidence_marker="neither X-Frame-Options nor CSP frame-ancestors present"))
    else:
        findings.append(wrap_finding(
            "Frame-embedding protection present — clickjacking mitigated.",
            severity="POSITIVE", cvss="0.0", cwe="N/A", owasp="A05:2021",
            remediation="No action needed; keep frame-busting headers enforced.",
            evidence_marker=f"X-Frame-Options={xfo or 'none'}; CSP frame-ancestors={has_fa}"))
    return standard_response(tool="clickjacking", target=req.target,
        findings=findings, tests_performed=1,
        tests_summary="Frame-embedding protection check",
        raw_data={"clickjacking": {"x_frame_options": xfo,
                                     "csp_frame_ancestors": has_fa,
                                     "spa_catchall": spa["is_spa"]}})
def register(app): app.include_router(router)
