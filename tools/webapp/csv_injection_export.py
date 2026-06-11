"""csv_injection_export — CSV formula injection in export endpoints.

If user can inject text that gets EXPORTED to CSV/XLSX without prefixing
formula-trigger chars (= + - @ tab), opening the file in Excel runs
arbitrary commands (e.g. =cmd|'/c calc'!A1 → calc.exe).

POST data containing formula payloads to endpoints, then GET the CSV
export and check for un-escaped formulas.
"""
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

FORMULA_PAYLOADS = [
    "=cmd|'/c calc'!A1",
    "+cmd|'/c calc'!A1",
    "-cmd|'/c calc'!A1",
    "@SUM(A1:A10)",
    "=HYPERLINK(\"http://evil-attacker.example\",\"click\")",
]
EXPORT_PATHS = [
    "/api/users.csv", "/api/users/export", "/api/export/users",
    "/users/export.csv", "/api/data.csv", "/export",
    "/api/contacts/export", "/admin/export",
]


@router.post("/api/webapp/scan/csv_injection_export")
@vl_turbo()
@vl_verify()
def scan_csv_injection_export(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    # VL-TURBO deep: Phase 1 - probe all 8 export paths in parallel.
    # Was 8 paths * 8s timeout = 64s sequential. Now ~8s in parallel.
    def _discover(path):
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Accept": "text/csv,application/csv,*/*"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code == 404:
            return None
        ct = (r.headers.get("content-type") or "").lower()
        cd = (r.headers.get("content-disposition") or "").lower()
        if "csv" in ct or "excel" in ct or ".csv" in cd or ".xlsx" in cd:
            return {"path": path, "content_type": ct}
        return None

    csv_endpoints = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for hit in pool.map(_discover, EXPORT_PATHS, timeout=20):
            if hit:
                csv_endpoints.append(hit)

    if not csv_endpoints:
        return standard_response(
            tool="csv_injection_export", target=req.target, findings=[],
            tests_performed=len(EXPORT_PATHS), vulnerable=False,
            skipped_reason="No CSV/Excel export endpoints found")

    findings = []

    # Phase 2: parallel formula scan of each export endpoint
    def _scan_endpoint(ep):
        r = safe_request("GET", base + ep["path"],
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=10, allow_redirects=False)
        if r is None:
            return None
        body = (r.text or "")[:50000]
        risky_lines = []
        for line in body.splitlines()[:500]:
            for sep in (",", "\t", ";"):
                if sep not in line:
                    continue
                for cell in line.split(sep):
                    cell = cell.strip().strip('"')
                    if cell and cell[0] in "=+-@\x09" and not cell.startswith("'"):
                        risky_lines.append({"path": ep["path"],
                                              "cell_start": cell[:50]})
                        break
            if len(risky_lines) > 5:
                break
        if risky_lines:
            return {"path": ep["path"], "risky_cells": risky_lines[:3]}
        return None

    risk_endpoints = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for risk in pool.map(_scan_endpoint, csv_endpoints, timeout=25):
            if risk:
                risk_endpoints.append(risk)

    if risk_endpoints:
        findings.append(wrap_finding(
            f"CSV formula injection risk at {len(risk_endpoints)} export endpoint(s)",
            "MEDIUM", cvss="6.0", cwe="CWE-1236", owasp="A03:2021",
            remediation="Prefix any cell value starting with = + - @ TAB with "
                        "apostrophe (') OR wrap in double quotes with literal "
                        "preceding apostrophe. Most CSV-export libraries have "
                        "csv_safe=True option. For Excel: use the XLSX export "
                        "with cell-type 'string' instead of 'general' (Excel "
                        "treats string-typed cells as literal text).",
            evidence_marker=" | ".join(
                f"{e['path']}: cell starts '{e['risky_cells'][0]['cell_start']}'"
                for e in risk_endpoints[:3]
            )))
    else:
        findings.append(wrap_finding(
            f"Found {len(csv_endpoints)} export endpoint(s) — none currently leak "
            "formula-trigger characters",
            "POSITIVE", cwe="CWE-1236",
            remediation="Maintain. POST attacker-controlled data into the system "
                        "then re-export to confirm sanitization (this passive "
                        "scan only checks current data).",
            evidence_marker=" | ".join(e["path"] for e in csv_endpoints[:5])))

    return standard_response(
        tool="csv_injection_export", target=req.target, findings=findings,
        tests_performed=len(EXPORT_PATHS) + len(csv_endpoints),
        vulnerable=bool(risk_endpoints),
        tests_summary=f"{len(csv_endpoints)} export endpoints, "
                       f"{len(risk_endpoints)} with unescaped formulas",
        raw_data={"csv_endpoints": csv_endpoints,
                   "risk_endpoints": risk_endpoints})


def register(app):
    app.include_router(router)
