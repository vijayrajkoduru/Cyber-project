"""regex_dos_probe — ReDoS detection via timing anomaly.

Catastrophic-backtracking regex patterns (e.g. (a+)+$ against
'aaaaaaaaaaaaaaaaaaaaaaab') can hang regex engines for seconds. Tests
endpoints that look like they validate input (registration, search) by
sending input strings known to trigger catastrophic backtracking against
common-vulnerable patterns:
  - Email validation regex
  - URL validation regex
  - Username validation

If response time is >5x baseline, flag for manual review.
"""
import time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

# Inputs designed to trigger catastrophic backtracking in classic vuln patterns
# (a+)+@... ; (a+a*)+x ; etc.
EVIL_INPUTS = [
    ("a" * 30 + "!",                "(a+)+ pattern catastrophic"),
    ("a" * 30 + "@" + "a" * 30 + "@",  "email regex (a+)+@(a+)+ form"),
    ("aaaaaaaaaaaaaaaaaaa" * 3 + "X",   "long-prefix catastrophic"),
    ("?" * 25 + "a" * 25,            "alternation catastrophic"),
]

# Endpoints to test
PROBE_PATHS = [
    ("GET",  "/?q={}"),
    ("GET",  "/search?q={}"),
    ("POST", "/api/register", {"email": "{}"}),
    ("POST", "/api/login", {"username": "{}"}),
    ("POST", "/api/contact", {"email": "{}"}),
]


def _request(method, url, params=None, data=None, req=None, timeout=15):
    if method == "GET":
        return safe_request("GET", url, params=params,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=timeout, allow_redirects=False)
    else:
        import json
        return safe_request("POST", url,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Content-Type": "application/json"},
            data=json.dumps(data), req=req, timeout=timeout, allow_redirects=False)


@router.post("/api/webapp/scan/regex_dos_probe")
@vl_turbo()
@vl_verify()
def scan_regex_dos_probe(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    suspicious = []
    tested = 0

    for spec in PROBE_PATHS:
        method = spec[0]
        path = spec[1]
        body_tpl = spec[2] if len(spec) > 2 else None
        # Sanity-baseline with benign value
        url = base + (path if "{}" not in path else path.format("test"))
        if body_tpl:
            body = {k: v.format("test") for k, v in body_tpl.items()}
            t0 = time.time()
            r0 = _request(method, base + path, data=body, req=req)
            baseline = time.time() - t0
        else:
            t0 = time.time()
            r0 = _request("GET", base + path.format("test"), req=req)
            baseline = time.time() - t0
        if r0 is None or r0.status_code == 404: continue
        tested += 1

        # Now hit with each evil input
        for evil, desc in EVIL_INPUTS:
            if body_tpl:
                body = {k: v.format(evil) for k, v in body_tpl.items()}
                t0 = time.time()
                r = _request(method, base + path, data=body, req=req, timeout=12)
                elapsed = time.time() - t0
            else:
                t0 = time.time()
                r = _request("GET", base + path.format(evil), req=req, timeout=12)
                elapsed = time.time() - t0
            # Vulnerable signal: response time > 5x baseline AND > 1.5s
            if baseline > 0 and elapsed > 5 * baseline and elapsed > 1.5:
                suspicious.append({
                    "path": path, "input": evil[:30] + "...",
                    "baseline_ms": int(baseline * 1000),
                    "evil_ms": int(elapsed * 1000),
                    "desc": desc,
                })
                break  # one finding per path is enough

    if suspicious:
        findings.append(wrap_finding(
            f"Possible ReDoS at {len(suspicious)} endpoint(s) — response time anomaly",
            "HIGH", cvss="7.5", cwe="CWE-1333", owasp="A04:2021",
            remediation="Endpoint responds >5x slower to crafted catastrophic-"
                        "backtracking input vs benign input. Audit your validation "
                        "regex for nested quantifiers (a+)+ / alternation followed by "
                        "overlap. Use re2 (non-backtracking) instead of stdlib re / "
                        "pcre. JS: switch to /v unicode-mode regex (Chrome 112+). "
                        "Or: cap input length + cap regex eval time-out.",
            evidence_marker=" | ".join(
                f"{s['path']}: baseline {s['baseline_ms']}ms → evil {s['evil_ms']}ms "
                f"({s['desc']})"
                for s in suspicious[:3]
            )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"No ReDoS time anomaly across {tested} endpoint(s)",
            "POSITIVE", cwe="CWE-1333",
            remediation="Maintain. Test deeper with regex-fuzz tools like ReDoSHunter "
                        "or rxxr if your code uses heavy regex validation.",
            evidence_marker=f"{tested} endpoints tested with 4 catastrophic inputs each"))
    else:
        return standard_response(
            tool="regex_dos_probe", target=req.target, findings=[],
            tests_performed=len(PROBE_PATHS), vulnerable=False,
            skipped_reason="None of the probe paths exist on target")

    return standard_response(
        tool="regex_dos_probe", target=req.target, findings=findings,
        tests_performed=len(PROBE_PATHS) * len(EVIL_INPUTS),
        vulnerable=bool(suspicious),
        tests_summary=f"{tested} endpoints, {len(suspicious)} ReDoS-suspect",
        raw_data={"suspicious_endpoints": suspicious})


def register(app):
    app.include_router(router)
