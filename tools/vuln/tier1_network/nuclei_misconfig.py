"""Nuclei misconfiguration templates — tag-specific fan-out (~1500 templates)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools.webapp._webapp_common import vuln_response
from tools._framework.nuclei_runner import run_nuclei

router = APIRouter()


@router.post("/api/vuln/nuclei_misconfig")
def scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    res = run_nuclei(req, tags=["misconfig", "exposure", "panel"],
                      severity_min="medium")
    if res["skipped"]:
        return vuln_response(tool="nuclei_misconfig", target=req.target, findings=[],
            tested=0, what_checked="Nuclei misconfig templates",
            skipped_reason=res["skipped"])
    return vuln_response(tool="nuclei_misconfig", target=req.target,
        findings=res["findings"], tested=res["tested"],
        what_checked="Nuclei community misconfig + exposure + exposed-panel templates (~1500)",
        tests_summary=f"Nuclei misconfig: {len(res['findings'])} match(es)",
        raw_data={"nuclei_misconfig": {"matches": res["raw"]}})


def register(app):
    app.include_router(router)
