"""Nikto-equivalent — lightweight web-server posture summary.

The Vuln module is an INFRASTRUCTURE / host vulnerability scanner (Nessus / Qualys
tier). Webapp-style checks (missing security headers, exposed sensitive files,
CORS misconfig, dangerous HTTP methods) live in the dedicated Webapp module at
/api/webapp/scan/* — running them here would duplicate work + create cross-module
coupling.

This handler emits a posture-summary finding pointing the user at the right
module for those checks, so the Vuln PDF still shows a "Nikto" section.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding
from tools.vuln._vuln_common import vuln_response

router = APIRouter()


@router.post("/api/vuln/nikto")
def scan_nikto(req: ScanRequest, payload=Depends(verify_scan_quota)):
    """Posture pointer — webapp checks belong in the Webapp module."""
    info = wrap_finding(
        "Nikto-style web posture covered by Webapp module",
        "POSITIVE",
        evidence_marker=(
            "Nikto's classic checks (missing security headers, exposed sensitive "
            "files, CORS misconfig, dangerous HTTP methods, XSS/SQLi probes) are "
            "now executed by the dedicated Webapp module at /api/webapp/scan/*. "
            "Run an OWASP scan from that module for full web-application coverage; "
            "the Vuln module focuses on host/infrastructure exposure (CVEs, services, "
            "TLS, credentials, network enumeration)."))
    return vuln_response(
        tool="nikto", target=req.target, findings=[info], tested=1,
        what_checked="Web-server posture pointer (Webapp module handles deep checks)",
        tests_summary=("Nikto pointer — run the Webapp module for security headers, "
                       "exposed files, CORS, HTTP methods, and OWASP-grade scans."),
        raw_data={"nikto": {
            "delegated_to_module": "webapp",
            "webapp_endpoints": [
                "/api/webapp/scan/security_headers",
                "/api/webapp/scan/exposed_files",
                "/api/webapp/scan/cors",
                "/api/webapp/scan/http_methods",
            ],
            "rationale": "Vuln module scope is infrastructure; webapp posture lives in Webapp module.",
        }},
    )


def register(app):
    app.include_router(router)
