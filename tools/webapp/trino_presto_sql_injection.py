"""trino_presto_sql_injection — Trino/Presto SQL endpoint detection + injection."""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
TRINO_PATHS = ["/v1/info", "/v1/statement", "/ui/", "/v1/cluster"]


@router.post("/api/webapp/scan/trino_presto_sql_injection")
@vl_turbo()
@vl_verify()
def scan_trino_presto_sql_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    is_trino = False
    sql_exec_works = False
    for path in TRINO_PATHS:
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0", "Accept": "application/json"},
            req=req, timeout=8, allow_redirects=False)
        if r is None: continue
        body = (r.text or "")[:5000]
        if "trino" in body.lower() or "presto" in body.lower() or "nodeId" in body:
            is_trino = True

    if is_trino:
        # Try executing a benign SQL statement
        r2 = safe_request("POST", base + "/v1/statement",
            headers={"Content-Type": "text/plain",
                      "User-Agent": "VulnusLab/1.0",
                      "X-Trino-User": "vulnuslab"},
            data="SELECT 1", req=req, timeout=8, allow_redirects=False)
        if r2 is not None and r2.status_code == 200:
            try:
                if "nextUri" in r2.json() or '"data"' in r2.text:
                    sql_exec_works = True
            except Exception: pass

    findings = []
    if sql_exec_works:
        findings.append(wrap_finding(
            "Trino/Presto SQL endpoint EXECUTES queries unauth",
            "CRITICAL", cvss="9.0", cwe="CWE-89", owasp="A05:2021",
            remediation="Trino must be behind authentication. Enable "
                        "PASSWORD or KERBEROS authenticator in coordinator. "
                        "Internet-exposed Trino = query any connected catalog "
                        "(Hive, MySQL, S3, ...) = exfil of structured data.",
            evidence_marker=f"POST /v1/statement with SELECT 1 → 200 + data"))
    elif is_trino:
        findings.append(wrap_finding(
            "Trino/Presto detected — verify auth enforcement",
            "INFO", cwe="CWE-200",
            remediation="Visible from internet OK if auth enforced; verify "
                        "/v1/statement returns 401 without credentials.",
            evidence_marker="Trino metadata exposed but query rejected"))
    else:
        findings.append(wrap_finding("No Trino/Presto detected", "POSITIVE",
            cwe="CWE-200", remediation="N/A",
            evidence_marker=f"checked {len(TRINO_PATHS)} Trino paths"))
    return standard_response(
        tool="trino_presto_sql_injection", target=req.target, findings=findings,
        tests_performed=len(TRINO_PATHS) + (1 if is_trino else 0),
        vulnerable=sql_exec_works,
        tests_summary=f"trino={is_trino}, sql_exec={sql_exec_works}",
        raw_data={"is_trino": is_trino, "sql_exec_unauth": sql_exec_works})


def register(app): app.include_router(router)
