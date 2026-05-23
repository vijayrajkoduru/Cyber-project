"""HTTP Methods -- checks for dangerous methods enabled.

Zero-FP rule: a method is "honoured" only if (a) the server's own Allow
header doesn't explicitly exclude it AND (b) the response differs from
a plain GET (so we know the server actually processed the method instead
of a CDN/proxy normalising every verb to GET and returning the homepage).
TRACE is special-cased: it's honoured only if the response body echoes
the request line back, which is the actual attack signature.
"""
import time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response, precheck_target
router = APIRouter()
_DANGEROUS = {
    "TRACE":  ("Cross-Site Tracing -- can leak cookies", "MEDIUM", "5.3"),
    "DELETE": ("Unauthenticated DELETE -- possible data destruction", "HIGH", "7.5"),
    "PUT":    ("Unauthenticated PUT -- possible file upload / RCE", "HIGH", "8.1"),
    "CONNECT":("CONNECT enabled -- possible open proxy", "MEDIUM", "5.3"),
    "PATCH":  ("PATCH enabled -- verify auth required", "LOW", "3.1"),
}


def _parse_allow(header: str) -> set:
    return {m.strip().upper() for m in (header or "").split(",") if m.strip()}


@router.post("/api/scan/http_methods")
def scan_http_methods(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    unreachable = precheck_target(url, req, active_probes=False)  # OPTIONS/TRACE probes — read-only
    if unreachable:
        return vuln_response(tool="http_methods", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    findings = []
    tested = []
    suppressed = []
    # VL-TURBO wall-clock cap: OPTIONS + GET + 5 methods × 10s × 3 retries = ~3.5 min worst.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 30.0
    _bailed = False

    # 1. Ask the server what it supports.
    options_resp = safe_request("OPTIONS", url, req=req, timeout=8, retries=0)
    allow_str = (options_resp.headers.get("Allow", "") if options_resp else "") or ""
    allowed_methods = _parse_allow(allow_str)

    # 2. Baseline GET so we can detect CDNs that return the homepage for any verb.
    get_resp = safe_request("GET", url, req=req, timeout=8, retries=0, allow_redirects=False)
    get_body_size = len(get_resp.content) if get_resp is not None else -1
    get_status = get_resp.status_code if get_resp is not None else -1

    for method, (detail, sev, cvss) in _DANGEROUS.items():
        if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
            _bailed = True; break
        try:
            r2 = safe_request(method, url, req=req, timeout=6, retries=0, allow_redirects=False)
        except Exception:
            continue
        if r2 is None:
            continue
        body_size = len(r2.content)
        tested.append({"method": method, "status": r2.status_code,
                       "body_size": body_size})

        # --- Server rejected it explicitly -- never a finding ---
        if r2.status_code in (405, 501) or r2.status_code >= 400:
            continue

        # --- Allow header is authoritative when present ---
        # If OPTIONS returned an Allow list and our method isn't on it, the
        # server is telling us this method is NOT supported -- whatever the
        # 2xx/3xx response was, it's CDN/framework noise, not real handling.
        if allowed_methods and method not in allowed_methods:
            suppressed.append({"method": method, "reason": "not_in_allow",
                               "allow": sorted(allowed_methods)})
            continue

        # --- TRACE: real only if the response echoes the request line ---
        if method == "TRACE":
            body = (r2.text or "")[:2000]
            if "TRACE " not in body.upper():
                suppressed.append({"method": "TRACE", "reason": "no_echo"})
                continue

        # --- CDN-normalised-to-GET filter ---
        # If the response body for a destructive method is byte-identical to
        # GET, the server didn't actually process it -- it normalised to GET
        # and returned the homepage. Real PUT/DELETE handlers return
        # something different (created/no-content/json/etc.).
        if get_body_size > 0 and body_size == get_body_size and \
           r2.status_code == get_status and method in ("PUT", "DELETE", "PATCH"):
            suppressed.append({"method": method, "reason": "identical_to_get",
                               "body_size": body_size})
            continue

        findings.append(wrap_finding(
            f"{method} method honoured -- {detail}",
            sev, cvss=cvss, cwe="CWE-749", owasp="A05:2021",
            remediation=f"Disable {method} at the web server / framework level.",
            evidence_marker=f"{method} {url} returned HTTP {r2.status_code} "
                            f"(allow={sorted(allowed_methods) or 'unset'})"))

    summary = (f"Probed {len(tested)}/{len(_DANGEROUS)} dangerous methods in "
               f"{time.time() - _wallclock_start:.1f}s; Allow: {allow_str!r}")
    if suppressed:
        summary += f"; {len(suppressed)} CDN-normalized methods filtered as non-vulnerable"
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return vuln_response(tool="http_methods", target=req.target,
        findings=findings, tested=max(len(tested), 1),
        what_checked="dangerous HTTP methods (TRACE/PUT/DELETE/CONNECT/PATCH)",
        tests_summary=summary,
        raw_data={"http_methods": {"allow_header": allow_str,
                                    "allowed_methods": sorted(allowed_methods),
                                    "methods_tested": tested,
                                    "suppressed_fps": suppressed,
                                    "wallclock_bailed": _bailed}})
def register(app): app.include_router(router)
