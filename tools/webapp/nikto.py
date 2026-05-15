"""Nikto-equivalent — aggregates 4 web-vulnerability scanners."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, standard_response

router = APIRouter()


@router.post("/api/scan/nikto")
async def scan_nikto(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.webapp.security_headers import scan_security_headers
    from tools.webapp.exposed_files import scan_exposed_files
    from tools.webapp.cors import scan_cors
    from tools.vuln.http_methods import scan_http_methods
    sub_scanners = [
        ("security_headers", scan_security_headers),
        ("exposed_files",    scan_exposed_files),
        ("cors",             scan_cors),
        ("http_methods",     scan_http_methods),
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
        tool="nikto", target=req.target, findings=all_findings,
        tests_performed=total_tests,
        tests_summary=f"Nikto-equivalent: {len(sub_scanners)} scanners aggregated ({total_tests} tests, {len(all_findings)} findings)",
        raw_data={"nikto": {"sub_scanners": sub_results}},
    )


def register(app):
    app.include_router(router)
