"""Nuclei RCE templates — tag-specific fan-out (~400 templates)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools.webapp._webapp_common import vuln_response
from tools._framework.nuclei_runner import run_nuclei

router = APIRouter()


@router.post("/api/webapp/scan/nuclei_rce")
def scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    res = run_nuclei(req, tags=["rce", "code-execution"], severity_min="high")
    if res["skipped"]:
        return vuln_response(tool="nuclei_rce", target=req.target, findings=[],
            tested=0, what_checked="Nuclei RCE templates",
            skipped_reason=res["skipped"])
    return vuln_response(tool="nuclei_rce", target=req.target,
        findings=res["findings"], tested=res["tested"],
        what_checked="Nuclei community RCE templates (high+critical only, ~400 templates)",
        tests_summary=f"Nuclei RCE: {len(res['findings'])} match(es)",
        raw_data={"nuclei_rce": {"matches": res["raw"]}})


def register(app):
    app.include_router(router)
