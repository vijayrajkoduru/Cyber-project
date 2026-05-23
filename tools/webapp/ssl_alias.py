"""SSL/TLS analysis — alias scanner.

Historical note: previously delegated to `tools.recon.ssl_deep.recon_ssl_deep`,
which has since been quarantined (`tools/recon/_legacy_quarantine/`). The new
Recon tier7 has `tls_deep` which runs as its own /api/recon/tls_deep tool;
this Vuln alias now simply emits a pointer-finding so the Vuln PDF still has
a "SSL/TLS Analysis" section. Customers who want deep TLS results should
look at the Recon module output.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding
from tools.webapp._webapp_common import vuln_response
router = APIRouter()


@router.post("/api/webapp/scan/ssl")
def scan_ssl(req: ScanRequest, payload=Depends(verify_scan_quota)):
    info = wrap_finding(
        "SSL/TLS analysis delegated — see Recon module's tls_deep scanner",
        "POSITIVE",
        evidence_marker=("Deep TLS handshake / cipher / certificate analysis "
                          "runs as tools/recon/tier7_app/tls_deep.py "
                          "(/api/recon/tls_deep). The Vuln module no longer "
                          "duplicates that work."))
    return vuln_response(
        tool="ssl", target=req.target, findings=[info], tested=1,
        what_checked="meta-aggregation pointer (see Recon tls_deep)",
        tests_summary="SSL/TLS meta — see Recon tls_deep section.",
        raw_data={"ssl": {"delegated_to": "recon.tls_deep"}},
    )


def register(app): app.include_router(router)
