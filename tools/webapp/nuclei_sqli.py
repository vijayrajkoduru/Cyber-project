"""Nuclei SQL Injection templates — tag-specific fan-out (~500 templates)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools.webapp._webapp_common import vuln_response
from tools._framework.nuclei_runner import run_nuclei

router = APIRouter()


@router.post("/api/webapp/scan/nuclei_sqli")
def scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    res = run_nuclei(req, tags=["sqli", "sql"], severity_min="medium")
    if res["skipped"]:
        return vuln_response(tool="nuclei_sqli", target=req.target, findings=[],
            tested=0, what_checked="Nuclei SQLi templates",
            skipped_reason=res["skipped"])
    return vuln_response(tool="nuclei_sqli", target=req.target,
        findings=res["findings"], tested=res["tested"],
        what_checked="Nuclei community SQLi templates (~500 templates)",
        tests_summary=f"Nuclei SQLi: {len(res['findings'])} match(es)",
        raw_data={"nuclei_sqli": {"matches": res["raw"]}})


def register(app):
    app.include_router(router)
