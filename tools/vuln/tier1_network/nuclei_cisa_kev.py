"""Nuclei CISA-KEV templates — confirmed exploited-in-the-wild CVEs (~600 templates).

This is the most-pressing slice of Nuclei: every template here corresponds to
a CVE on the CISA Known Exploited Vulnerabilities catalog. Hits here are not
hypothetical — they are actively used by attackers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url
from tools.webapp._webapp_common import vuln_response
from tools._vl_core.nuclei_runner import run_nuclei
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()


@router.post("/api/vuln/nuclei_cisa_kev")
@vl_turbo()
@vl_verify()
def scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanned_url = web_url(req.target)
    deadline = 90
    res = run_nuclei(req, tags=["kev"], severity_min="medium", timeout_s=deadline)
    if res["skipped"]:
        return vuln_response(tool="nuclei_cisa_kev", target=req.target, findings=[],
            tested=0, what_checked="Nuclei CISA-KEV templates",
            skipped_reason=res["skipped"])
    findings = res["findings"]
    if not findings:
        findings = [{
            "name": "No CISA-KEV CVEs detected",
            "severity": "POSITIVE",
            "remediation": "Maintain current patch cadence and continue tracking CISA BOD 22-01 / KEV additions as new known-exploited CVEs are published.",
            "evidence_marker": f"Nuclei CISA-KEV templates (~600) matched no actively-exploited CVE on {scanned_url}.",
        }]
    return vuln_response(tool="nuclei_cisa_kev", target=req.target,
        findings=findings, tested=res["tested"],
        what_checked="Nuclei CISA Known Exploited Vulnerabilities templates (~600)",
        tests_summary=f"Nuclei CISA-KEV: {len(res['findings'])} match(es) - actively exploited",
        raw_data={"nuclei_cisa_kev": {"matches": res["raw"]}})


def register(app):
    app.include_router(router)
