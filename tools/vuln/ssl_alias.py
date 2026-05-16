"""SSL/TLS analysis — alias to recon's ssl_deep at /api/scan/ssl."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            wrap_finding, standard_response)
router = APIRouter()
_CVSS = {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.5", "LOW": "3.5"}

@router.post("/api/scan/ssl")
async def scan_ssl(req: ScanRequest, payload=Depends(verify_scan_quota)):
    try:
        from tools.recon.ssl_deep import recon_ssl_deep
    except ImportError:
        return standard_response(tool="ssl", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="recon ssl_deep module not available")
    ssl_result = await recon_ssl_deep(req, payload)
    if not ssl_result.get("ok"):
        return standard_response(tool="ssl", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=ssl_result.get("skipped_reason", "TLS handshake failed"))
    findings = []
    for v in ssl_result.get("vulnerabilities", []):
        sev = v.get("severity", "MEDIUM")
        findings.append(wrap_finding(
            f"SSL/TLS: {v.get('name', 'issue')}",
            sev, cve=v.get("cve", "N/A"), cwe="CWE-326", owasp="A02:2021",
            remediation=v.get("remediation", "Review TLS config; disable weak protocols/ciphers."),
            evidence_marker=f"{ssl_result.get('host')}:{ssl_result.get('port')} — {ssl_result.get('current_protocol')}",
            cvss=_CVSS.get(sev, "5.0")))
    return standard_response(tool="ssl", target=req.target, findings=findings,
        tests_performed=max(len(ssl_result.get("vulnerabilities", [])), 1),
        tests_summary=f"SSL/TLS deep scan — {len(findings)} issue(s)",
        raw_data={"ssl": ssl_result})
def register(app): app.include_router(router)
