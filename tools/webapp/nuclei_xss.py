"""Nuclei XSS templates — tag-specific fan-out (~600 templates)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools.webapp._webapp_common import vuln_response
from tools._framework.nuclei_runner import run_nuclei

router = APIRouter()


@router.post("/api/webapp/scan/nuclei_xss")
def scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    res = run_nuclei(req, tags=["xss", "dom"], severity_min="medium")
    if res["skipped"]:
        return vuln_response(tool="nuclei_xss", target=req.target, findings=[],
            tested=0, what_checked="Nuclei XSS templates",
            skipped_reason=res["skipped"])
    return vuln_response(tool="nuclei_xss", target=req.target,
        findings=res["findings"], tested=res["tested"],
        what_checked="Nuclei community XSS + DOM templates (~600 templates)",
        tests_summary=f"Nuclei XSS: {len(res['findings'])} match(es)",
        raw_data={"nuclei_xss": {"matches": res["raw"]}})


def register(app):
    app.include_router(router)
