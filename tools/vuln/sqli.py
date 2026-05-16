"""Time-based blind SQL injection — triple-confirmation zero-FP."""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()
_PAYLOADS = [
    ("mysql_int",  "1 AND SLEEP({N})",                                "MySQL"),
    ("mysql_str",  "1' AND SLEEP({N})-- -",                           "MySQL"),
    ("pgsql_int",  "1 AND pg_sleep({N})",                             "PostgreSQL"),
    ("pgsql_str",  "1' AND pg_sleep({N})-- -",                        "PostgreSQL"),
    ("mssql_str",  "1'; WAITFOR DELAY '0:0:{N}'-- -",                 "MSSQL"),
    ("oracle_str", "1' AND dbms_pipe.receive_message(('a'),{N})-- -", "Oracle"),
]

def _time_get(url, req, timeout):
    t0 = time.time()
    r = safe_get(url, req=req, allow_redirects=True, timeout=timeout)
    return r, time.time() - t0

@router.post("/api/scan/sqli")
async def scan_sqli(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    parsed = urlparse(base)
    params = parse_qs(parsed.query)
    if not params:
        return standard_response(tool="sqli", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters present — append ?id=1 (or similar) to test")
    findings, tests, confirmed = [], 0, []
    _, t0 = _time_get(base, req, timeout=20)
    for key in list(params.keys())[:3]:
        for name, tmpl, db in _PAYLOADS:
            tests += 1
            payload5 = tmpl.replace("{N}", "5")
            new_params = {k: v[0] for k, v in params.items()}
            new_params[key] = payload5
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            _, t1 = _time_get(test_url, req, timeout=25)
            if t1 < t0 + 4: continue
            payload2 = tmpl.replace("{N}", "2")
            new_params[key] = payload2
            test_url2 = urlunparse(parsed._replace(query=urlencode(new_params)))
            _, t2 = _time_get(test_url2, req, timeout=15)
            if t2 > t0 + 1 and t1 > t2:
                findings.append(wrap_finding(
                    f"Time-based blind SQLi in {key!r} ({db})",
                    "CRITICAL", cvss="9.8", cwe="CWE-89", owasp="A03:2021",
                    remediation="Use parameterised queries (prepared statements). Never concatenate user input into SQL.",
                    evidence_marker=f"param={key} SLEEP(5)={t1:.2f}s, SLEEP(2)={t2:.2f}s, baseline={t0:.2f}s"))
                confirmed.append({"param": key, "db": db, "t0": t0, "t1": t1, "t2": t2})
                break
    return standard_response(tool="sqli", target=req.target, findings=findings,
        tests_performed=max(tests, 1),
        tests_summary=f"Time-based SQLi: {tests} payloads, triple-confirmation via SLEEP(5)+SLEEP(2)",
        raw_data={"sqli": {"confirmed": confirmed, "baseline_seconds": t0}})
def register(app): app.include_router(router)
