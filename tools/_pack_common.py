"""Shared helper for advisory-pack modules built from module_playbooks/.

Each pack module imports `make_advisory_router(module_name, techniques)`
and registers it. Eliminates ~30 lines of boilerplate per module.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding


def _adv_response(tool: str, target: str, title: str, sev: str, cvss: str,
                   cwe: str = "CWE-1395", remediation: str = "",
                   evidence: str = "") -> dict:
    return {
        "tool": tool, "target": target, "scan_time": 0,
        "vulnerable": sev in ("CRITICAL", "HIGH", "MEDIUM"),
        "severity": sev,
        "findings": [wrap_finding(
            title, sev, cvss=cvss, cwe=cwe, owasp="A05:2021",
            remediation=remediation or "See corresponding module_playbooks/*.md technique entry.",
            evidence_marker=evidence or "Advisory — see playbook + EDR/NSM detection guidance."
        )],
        "tests_performed": 1, "tests_summary": title[:80], "raw_data": {}
    }


def make_advisory_router(module_name: str, techniques: list,
                          playbook_ref: str = "") -> APIRouter:
    """Build an APIRouter registering one POST endpoint per technique.

    techniques: list of (slug, title, sev, cvss[, cwe[, remediation]]) tuples.
    """
    router = APIRouter()

    def _make(slug, title, sev, cvss, cwe, remed):
        def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
            return _adv_response(slug, req.target, title, sev, cvss, cwe=cwe,
                                  remediation=remed)
        _h.__name__ = slug
        return _h

    for t in techniques:
        # Tuple shape: (slug, title, sev, cvss, [cwe], [remediation])
        slug = t[0]; title = t[1]; sev = t[2]; cvss = t[3]
        cwe = t[4] if len(t) > 4 else "CWE-1395"
        remed = t[5] if len(t) > 5 else playbook_ref
        router.add_api_route(
            f"/api/{module_name}/{slug}",
            _make(slug, title, sev, cvss, cwe, remed),
            methods=["POST"],
        )

    return router
