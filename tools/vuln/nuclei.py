"""Nuclei-equivalent — aggregates 9 OWASP-grade active scanners."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, standard_response
router = APIRouter()

@router.post("/api/scan/nuclei")
async def scan_nuclei(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.vuln.xss import scan_xss
    from tools.vuln.sqli import scan_sqli
    from tools.vuln.cmd_injection import scan_cmd_injection
    from tools.vuln.lfi import scan_lfi
    from tools.vuln.open_redirect import scan_open_redirect
    from tools.vuln.ssrf import scan_ssrf
    from tools.vuln.xxe import scan_xxe
    from tools.vuln.csrf import scan_csrf
    from tools.vuln.jwt_scan import scan_jwt
    subs = [("xss", scan_xss), ("sqli", scan_sqli), ("cmd_injection", scan_cmd_injection),
            ("lfi", scan_lfi), ("open_redirect", scan_open_redirect), ("ssrf", scan_ssrf),
            ("xxe", scan_xxe), ("csrf", scan_csrf), ("jwt", scan_jwt)]
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
    return standard_response(tool="nuclei", target=req.target, findings=all_findings,
        tests_performed=total,
        tests_summary=f"Nuclei-equivalent: {len(subs)} OWASP scanners aggregated ({total} tests, {len(all_findings)} findings)",
        raw_data={"nuclei": {"sub_scanners": sub_results}})
def register(app): app.include_router(router)
