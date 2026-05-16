"""Nikto-equivalent — aggregates 4 passive web-vuln scanners."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, standard_response
router = APIRouter()

@router.post("/api/scan/nikto")
async def scan_nikto(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.vuln.security_headers import scan_security_headers
    from tools.vuln.exposed_files import scan_exposed_files
    from tools.vuln.cors import scan_cors
    from tools.vuln.http_methods import scan_http_methods
    subs = [("security_headers", scan_security_headers), ("exposed_files", scan_exposed_files),
            ("cors", scan_cors), ("http_methods", scan_http_methods)]
    all_findings, sub_results, total = [], {}, 0
    for name, fn in subs:
        try:
            r = await fn(req, payload)
            for f in r.get("findings", []):
                f["source_tool"] = name
                all_findings.append(f)
            total += r.get("tests_performed", 0)
            sub_results[name] = {"findings_count": len(r.get("findings", [])),
                                 "tests": r.get("tests_performed", 0),
                                 "skipped_reason": r.get("skipped_reason")}
        except Exception as e:
            sub_results[name] = {"error": str(e)[:120]}
    return standard_response(tool="nikto", target=req.target, findings=all_findings,
        tests_performed=total,
        tests_summary=f"Nikto-equivalent: {len(subs)} scanners aggregated ({total} tests, {len(all_findings)} findings)",
        raw_data={"nikto": {"sub_scanners": sub_results}})
def register(app): app.include_router(router)
