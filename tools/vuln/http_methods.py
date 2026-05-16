"""HTTP Methods — checks for dangerous methods enabled."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
router = APIRouter()
_DANGEROUS = {
    "TRACE":  ("Cross-Site Tracing — can leak cookies", "MEDIUM", "5.3"),
    "DELETE": ("Unauthenticated DELETE — possible data destruction", "HIGH", "7.5"),
    "PUT":    ("Unauthenticated PUT — possible file upload / RCE", "HIGH", "8.1"),
    "CONNECT":("CONNECT enabled — possible open proxy", "MEDIUM", "5.3"),
    "PATCH":  ("PATCH enabled — verify auth required", "LOW", "3.1"),
}

@router.post("/api/scan/http_methods")
async def scan_http_methods(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    tested = []
    r = safe_request("OPTIONS", url, req=req, timeout=10)
    allow = (r.headers.get("Allow", "") if r else "") or ""
    for method, (detail, sev, cvss) in _DANGEROUS.items():
        try:
            r2 = safe_request(method, url, req=req, timeout=8, allow_redirects=False)
        except Exception:
            continue
        if r2 is None: continue
        tested.append({"method": method, "status": r2.status_code})
        if r2.status_code not in (405, 501) and 200 <= r2.status_code < 400:
            findings.append(wrap_finding(
                f"{method} method honoured — {detail}",
                sev, cvss=cvss, cwe="CWE-749", owasp="A05:2021",
                remediation=f"Disable {method} at the web server / framework level.",
                evidence_marker=f"{method} {url} returned HTTP {r2.status_code}"))
    return standard_response(tool="http_methods", target=req.target,
        findings=findings, tests_performed=len(_DANGEROUS),
        tests_summary=f"Probed 5 dangerous methods individually; Allow: {allow!r}",
        raw_data={"http_methods": {"allow_header": allow, "methods_tested": tested}})
def register(app): app.include_router(router)
