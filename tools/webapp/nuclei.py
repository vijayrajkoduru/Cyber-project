"""Nuclei-equivalent — aggregates OWASP-grade vuln scanners."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, standard_response

router = APIRouter()


@router.post("/api/scan/nuclei")
async def scan_nuclei(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.webapp.xss import scan_xss
    from tools.webapp.sqli import scan_sqli
    from tools.webapp.lfi import scan_lfi
    from tools.webapp.open_redirect import scan_open_redirect
    from tools.webapp.ssrf import scan_ssrf
    from tools.webapp.xxe import scan_xxe
    from tools.webapp.csrf import scan_csrf
    from tools.webapp.jwt_scan import scan_jwt
    sub_scanners = [
        ("xss", scan_xss), ("sqli", scan_sqli), ("lfi", scan_lfi),
        ("open_redirect", scan_open_redirect), ("ssrf", scan_ssrf),
        ("xxe", scan_xxe), ("csrf", scan_csrf), ("jwt", scan_jwt),
    ]
    all_findings = []
    sub_results = {}
    total_tests = 0
    for name, fn in sub_scanners:
        try:
            result = await fn(req, payload)
            all_findings.extend(result.get("findings", []))
            total_tests += result.get("tests_performed", 0)
            sub_results[name] = {"tests": result.get("tests_performed", 0),
                                 "findings": len(result.get("findings", [])),
                                 "skipped_reason": result.get("skipped_reason")}
        except Exception as e:
            sub_results[name] = {"error": str(e)[:120]}
    return standard_response(
        tool="nuclei", target=req.target, findings=all_findings,
        tests_performed=total_tests,
        tests_summary=f"Nuclei-equivalent: {len(sub_scanners)} OWASP-grade scanners ({total_tests} tests, {len(all_findings)} findings)",
        raw_data={"nuclei": {"sub_scanners": sub_results}},
    )


def register(app):
    app.include_router(router)
