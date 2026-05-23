"""Nikto-equivalent — meta-scanner that aggregates results from 4 standalone scanners.

V2 (post-orchestrator-stall fix): we used to re-run security_headers + exposed_files +
cors + http_methods SERIALLY inside this handler. But those four scanners ALSO run in
the same orchestrator pass as standalone tools. Net effect: 4× duplicate work AND nikto
held an orchestrator semaphore slot for the WHOLE serial duration (60-120s), starving
the other 11 queued scanners.

Fix: return immediately with a pointer-finding so the PDF still has a "Nikto" section,
but the actual content lives in the standalone security_headers / exposed_files / cors /
http_methods sections. Zero duplicate HTTP traffic against the customer's target.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding
from tools.vuln._vuln_common import vuln_response
router = APIRouter()

_DELEGATED_TO = ["security_headers", "exposed_files", "cors", "http_methods"]


@router.post("/api/vuln/nikto")
def scan_nikto(req: ScanRequest, payload=Depends(verify_scan_quota)):
    """Lightweight meta-scanner — defers all active work to the 4 standalone
    scanners that the same orchestrator pass already runs in parallel."""
    info = wrap_finding(
        "Nikto coverage delegated — see standalone scanners",
        "POSITIVE",
        evidence_marker=("Nikto's web-vulnerability checks (missing security headers, "
                          "exposed sensitive files, CORS misconfig, dangerous HTTP "
                          "methods) are executed by 4 dedicated scanners that run in "
                          "the same orchestrator pass: "
                          + ", ".join(_DELEGATED_TO) + ". Consolidating prevented "
                          "duplicate HTTP traffic against the target and unblocked "
                          "the orchestrator queue."))
    return vuln_response(
        tool="nikto", target=req.target, findings=[info], tested=1,
        what_checked="meta-aggregation pointer (see standalone scanners)",
        tests_summary=("Nikto meta — actual findings live in "
                       + " / ".join(_DELEGATED_TO) + " sections."),
        raw_data={"nikto": {"delegated_to": _DELEGATED_TO,
                             "rationale": "avoid duplicate active probes during parallel orchestrator pass"}},
    )


def register(app): app.include_router(router)
