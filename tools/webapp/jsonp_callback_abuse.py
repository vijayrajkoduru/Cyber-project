"""jsonp_callback_abuse — JSONP endpoint detection + callback param abuse.

JSONP endpoints (e.g. /api/users?callback=foo) wrap response in
foo({...}). Pre-CORS technique, mostly dead — but legacy endpoints
still exist. Risk: callback parameter reflected without validation
= XSS (callback=alert(1) wraps JSON in alert(1)({...}) → execute).
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

CALLBACK_PARAMS = ["callback", "jsonp", "cb", "jsonpcallback", "json_callback"]
PROBE_PATHS = [
    "/", "/api/users", "/api/me", "/api/data",
    "/api/v1/users", "/data.json", "/users.json",
]


def _probe(url, params, req):
    return safe_request("GET", url, params=params,
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/jsonp_callback_abuse")
@vl_turbo()
@vl_verify()
def scan_jsonp_callback_abuse(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    jsonp_found = []
    xss_via_callback = []
    tested = 0

    for path in PROBE_PATHS:
        url = base + path
        # Baseline (no callback)
        r0 = _probe(url, {}, req)
        if r0 is None or r0.status_code == 404: continue
        tested += 1
        baseline_body = (r0.text or "")[:1000]

        for param in CALLBACK_PARAMS:
            # Test with benign callback name
            r = _probe(url, {param: "vulnuslab_cb"}, req)
            if r is None: continue
            body = (r.text or "")[:5000]
            # JSONP detection: response starts with our callback name + (
            if body.lstrip().startswith("vulnuslab_cb(") or "vulnuslab_cb({" in body:
                jsonp_found.append({"path": path, "param": param})
                # Now test XSS payload — alert(1)({...})
                r_evil = _probe(url, {param: "alert(1)"}, req)
                if r_evil is None: continue
                body_evil = (r_evil.text or "")[:5000]
                if body_evil.lstrip().startswith("alert(1)(") or "alert(1)({" in body_evil:
                    xss_via_callback.append({"path": path, "param": param,
                                               "snippet": body_evil[:100]})
                break  # one param per path

    findings = []
    if xss_via_callback:
        findings.append(wrap_finding(
            f"JSONP callback XSS at {len(xss_via_callback)} endpoint(s)",
            "HIGH", cvss="7.5", cwe="CWE-79", owasp="A03:2021",
            remediation="JSONP callback parameter not validated → reflected XSS. "
                        "(1) Whitelist callback names to /^[a-zA-Z0-9_]+$/ — reject "
                        "everything else. (2) Better: migrate to CORS — JSONP is "
                        "obsolete since CORS shipped (2014). (3) Set "
                        "X-Content-Type-Options: nosniff so MIME confusion can't "
                        "execute JSONP response as JS even if injected.",
            evidence_marker=" | ".join(
                f"{e['path']}?{e['param']}=alert(1) → {e['snippet'][:60]}"
                for e in xss_via_callback[:3]
            )))
    elif jsonp_found:
        findings.append(wrap_finding(
            f"JSONP endpoints detected ({len(jsonp_found)}) — callback names validated",
            "INFO", cwe="CWE-200",
            remediation="JSONP works but callback names appear validated. Consider "
                        "migrating to CORS for modern interop.",
            evidence_marker=" | ".join(f"{e['path']}?{e['param']}=" for e in jsonp_found[:5])))
    elif tested > 0:
        findings.append(wrap_finding(
            f"No JSONP endpoints detected ({tested} paths probed)",
            "POSITIVE", cwe="CWE-79",
            remediation="Maintain. JSONP is mostly dead and that's good — CORS "
                        "is the modern equivalent.",
            evidence_marker=f"{tested} probes × {len(CALLBACK_PARAMS)} callback param names"))
    else:
        return standard_response(
            tool="jsonp_callback_abuse", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="No reachable probe paths")

    return standard_response(
        tool="jsonp_callback_abuse", target=req.target, findings=findings,
        tests_performed=tested * len(CALLBACK_PARAMS),
        vulnerable=bool(xss_via_callback),
        tests_summary=f"{tested} paths, {len(jsonp_found)} JSONP, {len(xss_via_callback)} XSS",
        raw_data={"jsonp_endpoints": jsonp_found, "xss_via_callback": xss_via_callback})


def register(app):
    app.include_router(router)
