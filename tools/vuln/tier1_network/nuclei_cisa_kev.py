"""Nuclei CISA-KEV templates — confirmed exploited-in-the-wild CVEs (~600 templates).

This is the most-pressing slice of Nuclei: every template here corresponds to
a CVE on the CISA Known Exploited Vulnerabilities catalog. Hits here are not
hypothetical — they are actively used by attackers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools.webapp._webapp_common import vuln_response
from tools._framework.nuclei_runner import run_nuclei

router = APIRouter()


@router.post("/api/vuln/nuclei_cisa_kev")
def scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    res = run_nuclei(req, tags=["kev"], severity_min="medium")
    if res["skipped"]:
        return vuln_response(tool="nuclei_cisa_kev", target=req.target, findings=[],
            tested=0, what_checked="Nuclei CISA-KEV templates",
            skipped_reason=res["skipped"])
    return vuln_response(tool="nuclei_cisa_kev", target=req.target,
        findings=res["findings"], tested=res["tested"],
        what_checked="Nuclei CISA Known Exploited Vulnerabilities templates (~600)",
        tests_summary=f"Nuclei CISA-KEV: {len(res['findings'])} match(es) - actively exploited",
        raw_data={"nuclei_cisa_kev": {"matches": res["raw"]}})


def register(app):
    app.include_router(router)
