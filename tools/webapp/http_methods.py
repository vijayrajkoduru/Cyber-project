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
                            safe_request, wrap_finding)
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
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


@router.post("/api/webapp/scan/http_methods")
@vl_turbo()
@vl_verify()
def scan_http_methods(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    unreachable = precheck_target(url, req, active_probes=False)  # OPTIONS/TRACE probes — read-only
    if unreachable:
        return vuln_response(tool="http_methods", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)
    findings = []
    tested = []
    suppressed = []
    spa_suppressed = []
    # VL-VERIFY: detect SPA catch-all so we can drop method-honoured hits
    # whose body is byte-identical to the SPA shell.
    spa = detect_spa_catchall_sync(url)
    # VL-TURBO wall-clock cap: OPTIONS + GET + 5 methods × 10s × 3 retries = ~3.5 min worst.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 30.0
    _bailed = False

    # 0. Follow a single HTTP->HTTPS (or host) redirect before establishing
    #    baseline. Without this, a 308 redirect at line 0 makes every dangerous
    #    method look like it "passed through" since 3xx < 400 and the body is
    #    empty (defeats the identical-to-GET filter). See DELETE-FP-V2.
    _redirect_followed = None
    pre_get = safe_request("GET", url, req=req, timeout=8, retries=0, allow_redirects=False)
    if pre_get is not None and 300 <= pre_get.status_code < 400:
        loc = (pre_get.headers.get("Location") or "").strip()
        if loc:
            # Resolve relative redirects
            from urllib.parse import urljoin
            new_url = urljoin(url, loc)
            # Sanity: only follow if same host or http->https upgrade on same host
            try:
                from urllib.parse import urlparse
                old_p = urlparse(url); new_p = urlparse(new_url)
                same_host = (old_p.hostname or "") == (new_p.hostname or "")
                if same_host and new_url != url:
                    _redirect_followed = {"from": url, "to": new_url,
                                            "status": pre_get.status_code}
                    url = new_url
            except Exception:
                pass

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

        # --- 3xx redirect: server hasn't processed the verb, just redirecting.
        # A 301/302/307/308 to https:// or another host means the request was
        # never evaluated by an application handler. Suppress.
        if 300 <= r2.status_code < 400:
            suppressed.append({"method": method, "reason": "redirect_not_processed",
                               "status": r2.status_code,
                               "location": (r2.headers.get("Location") or "")[:120]})
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

        # VL-VERIFY: SPA shell — server returned the React/Vue index.html for
        # this method; it didn't really process the verb.
        if spa["is_spa"] and is_same_as_canary(r2.text or "", spa["canary_body"]):
            spa_suppressed.append({"method": method, "reason": "spa_shell"})
            continue

        findings.append(wrap_finding(
            f"{method} method honoured -- {detail}",
            sev, cvss=cvss, cwe="CWE-749", owasp="A05:2021",
            remediation=f"Disable {method} at the web server / framework level.",
            evidence_marker=f"{method} {url} returned HTTP {r2.status_code} "
                            f"(allow={sorted(allowed_methods) or 'unset'})"))

    summary = (f"Probed {len(tested)}/{len(_DANGEROUS)} dangerous methods in "
               f"{time.time() - _wallclock_start:.1f}s; Allow: {allow_str!r}")
    if _redirect_followed:
        summary += (f"; followed {_redirect_followed['status']} redirect "
                    f"{_redirect_followed['from']} -> {_redirect_followed['to']}")
    if suppressed:
        summary += f"; {len(suppressed)} method(s) filtered as non-vulnerable (CDN/redirect/etc.)"
    if spa_suppressed:
        summary += f"; {len(spa_suppressed)} SPA-shell suppression(s)"
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return vuln_response(tool="http_methods", target=req.target,
        findings=findings, tested=max(len(tested), 1),
        what_checked="dangerous HTTP methods (TRACE/PUT/DELETE/CONNECT/PATCH)",
        severity_when_clean="POSITIVE",
        tests_summary=summary,
        raw_data={"http_methods": {"allow_header": allow_str,
                                    "allowed_methods": sorted(allowed_methods),
                                    "methods_tested": tested,
                                    "suppressed_fps": suppressed,
                                    "spa_catchall": spa["is_spa"],
                                    "spa_suppressed": spa_suppressed,
                                    "redirect_followed": _redirect_followed,
                                    "wallclock_bailed": _bailed}})
def register(app): app.include_router(router)
