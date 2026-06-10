"""Nuclei default-credentials templates — tag-specific fan-out (~600 templates)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools.webapp._webapp_common import vuln_response
from tools._vl_core.nuclei_runner import run_nuclei
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()


@router.post("/api/webapp/scan/nuclei_default_creds")
@vl_turbo()
@vl_verify()
def scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    res = run_nuclei(req, tags=["default-login", "default-page", "weak-credentials"],
                      severity_min="medium")
    if res["skipped"]:
        return vuln_response(tool="nuclei_default_creds", target=req.target, findings=[],
            tested=0, what_checked="Nuclei default-credentials templates",
            skipped_reason=res["skipped"])
    return vuln_response(tool="nuclei_default_creds", target=req.target,
        findings=res["findings"], tested=res["tested"],
        what_checked="Nuclei community default-login + weak-credentials templates (~600)",
        tests_summary=f"Nuclei default-creds: {len(res['findings'])} match(es)",
        raw_data={"nuclei_default_creds": {"matches": res["raw"]}})


def register(app):
    app.include_router(router)
