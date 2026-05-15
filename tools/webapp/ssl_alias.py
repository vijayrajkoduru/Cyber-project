"""SSL/TLS scanner at /api/scan/ssl — wraps /api/recon/ssl_deep."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, wrap_finding, standard_response)

router = APIRouter()

_CVSS_BY_SEV = {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.5", "LOW": "3.5"}


@router.post("/api/scan/ssl")
async def scan_ssl(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.recon_module import recon_ssl_deep
    ssl_result = await recon_ssl_deep(req, payload)
    if not ssl_result.get("ok"):
        return standard_response(
            tool="ssl", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=ssl_result.get("skipped_reason", "TLS handshake failed"),
        )
    findings = []
    for v in ssl_result.get("vulnerabilities", []):
        sev = v.get("severity", "MEDIUM")
        findings.append(wrap_finding(
            f"SSL/TLS: {v.get('name', 'issue')}",
            sev, cve=v.get("cve", "N/A"),
            evidence_marker=f"{ssl_result.get('host')}:{ssl_result.get('port')} — current protocol: {ssl_result.get('current_protocol')}",
            remediation=v.get("remediation", "Review TLS configuration."),
            cvss=_CVSS_BY_SEV.get(sev, "5.0"),
            tests_performed=1,
        ))
    return standard_response(
        tool="ssl", target=req.target, findings=findings,
        tests_performed=max(len(ssl_result.get("vulnerabilities", [])), 1),
        tests_summary=f"SSL/TLS deep scan via ssl_deep — {len(findings)} issue(s) found",
        raw_data={"ssl": ssl_result},
    )


def register(app):
    app.include_router(router)
