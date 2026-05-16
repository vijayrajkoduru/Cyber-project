"""OS Command Injection — timing-based zero-FP."""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()
_PAYLOADS = [
    ("Linux semicolon", ";sleep {N}"),
    ("Linux pipe",      "|sleep {N}"),
    ("Linux subshell",  "$(sleep {N})"),
    ("Linux backtick",  "`sleep {N}`"),
    ("Linux ampersand", "&& sleep {N}"),
    ("Linux newline",   "%0asleep%20{N}"),
    ("Windows amp",     "& timeout /T {N}"),
    ("Windows logical", "&& timeout /T {N}"),
]

def _time_get(url, req, timeout):
    t0 = time.time()
    r = safe_get(url, req=req, allow_redirects=True, timeout=timeout)
    return r, time.time() - t0

@router.post("/api/scan/cmd_injection")
async def scan_cmd_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    parsed = urlparse(base)
    params = parse_qs(parsed.query)
    if not params:
        return standard_response(tool="cmd_injection", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters present — append ?cmd=ls (or similar) to test")
    findings, tests = [], 0
    _, t0 = _time_get(base, req, timeout=20)
    for key in list(params.keys())[:3]:
        original = params[key][0]
        for name, tmpl in _PAYLOADS:
            tests += 1
            inj5 = tmpl.replace("{N}", "5")
            new_params = {k: v[0] for k, v in params.items()}
            new_params[key] = original + inj5
            url1 = urlunparse(parsed._replace(query=urlencode(new_params)))
            _, t1 = _time_get(url1, req, timeout=25)
            if t1 < t0 + 4: continue
            inj2 = tmpl.replace("{N}", "2")
            new_params[key] = original + inj2
            url2 = urlunparse(parsed._replace(query=urlencode(new_params)))
            _, t2 = _time_get(url2, req, timeout=15)
            if t2 > t0 + 1 and t1 > t2:
                findings.append(wrap_finding(
                    f"OS command injection in {key!r} via {name}",
                    "CRITICAL", cvss="9.8", cwe="CWE-78", owasp="A03:2021",
                    remediation="Never pass user input to a shell. Use argv-style exec (shell=False).",
                    evidence_marker=f"param={key} {inj5!r}={t1:.2f}s, {inj2!r}={t2:.2f}s, baseline={t0:.2f}s"))
                break
    return standard_response(tool="cmd_injection", target=req.target, findings=findings,
        tests_performed=max(tests, 1),
        tests_summary=f"Cmd injection: {tests} shell-metachar payloads with timing confirmation",
        raw_data={"cmd_injection": {"baseline_seconds": t0}})
def register(app): app.include_router(router)
