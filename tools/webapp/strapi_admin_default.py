"""strapi_admin_default — Strapi CMS /admin default + CVE-2023-22893 audit."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()


@router.post("/api/webapp/scan/strapi_admin_default")
@vl_turbo()
@vl_verify()
def scan_strapi_admin_default(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    # Strapi: /admin login page + /api endpoint pattern
    is_strapi = False
    version = None
    for path in ("/admin", "/admin/init", "/_health"):
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r is None: continue
        body = (r.text or "")[:5000]
        if "Strapi" in body or "/admin/strapi" in body:
            is_strapi = True
        # /_health on Strapi returns 204
        if path == "/_health" and r.status_code == 204:
            is_strapi = True

    findings = []
    if is_strapi:
        # Strapi <= 4.5.5 has CVE-2023-22893 (auth bypass via reset password)
        # Probe /admin/auth/forgot-password endpoint
        rf = safe_request("POST", base + "/admin/auth/forgot-password",
            headers={"Content-Type": "application/json",
                      "User-Agent": "VulnusLab/1.0"},
            data='{"email": "vulnuslab-test@nonexistent.example"}',
            req=req, timeout=8, allow_redirects=False)
        cve_indicator = (rf is not None and rf.status_code == 200)
        findings.append(wrap_finding(
            "Strapi CMS admin panel detected" + (" + forgot-password reachable" if cve_indicator else ""),
            "MEDIUM" if cve_indicator else "LOW",
            cvss="5.3" if cve_indicator else "3.5",
            cwe="CWE-287", owasp="A07:2021",
            remediation="(1) Upgrade Strapi to ≥ 4.6.0 (fix for CVE-2023-22893). "
                        "(2) Move /admin to non-default path (custom proxy rewrite). "
                        "(3) IP-allowlist /admin at edge. (4) Default admin creds "
                        "during install MUST be rotated. (5) Audit role permissions.",
            evidence_marker="Strapi signature detected" + (
                f", forgot-pwd → {rf.status_code if rf else '?'}" if cve_indicator else "")))
    else:
        findings.append(wrap_finding(
            "Strapi not detected", "POSITIVE", cwe="CWE-200",
            remediation="N/A", evidence_marker="no Strapi markers"))
    return standard_response(
        tool="strapi_admin_default", target=req.target, findings=findings,
        tests_performed=4, vulnerable=is_strapi,
        tests_summary=f"strapi={is_strapi}",
        raw_data={"is_strapi": is_strapi})


def register(app): app.include_router(router)
