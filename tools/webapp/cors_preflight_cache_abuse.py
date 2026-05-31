"""cors_preflight_cache_abuse — Access-Control-Max-Age abuse audit.

Access-Control-Max-Age caches CORS preflight result in the browser. If
set to a long value (e.g. 86400 = 24h) AND your CORS policy CHANGES,
attacker can still abuse old, more-permissive cache for a day. Modern
browsers cap this — Chrome at 2h, Firefox at 24h.

Also: if A-C-Max-Age is enormous (years), it's a smell — likely copy-paste
default rather than a deliberate decision.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()


@router.post("/api/webapp/scan/cors_preflight_cache_abuse")
def scan_cors_preflight_cache_abuse(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target).rstrip("/")

    # Trigger preflight by sending OPTIONS with the typical CORS preflight headers
    r = safe_request("OPTIONS", url + "/",
        headers={"User-Agent": "VulnusLab/1.0",
                  "Origin": "https://attacker.example",
                  "Access-Control-Request-Method": "DELETE",
                  "Access-Control-Request-Headers": "Authorization, X-Custom-Header"},
        req=req, timeout=8, allow_redirects=False)
    if r is None:
        return standard_response(
            tool="cors_preflight_cache_abuse", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No response to preflight OPTIONS")

    max_age = r.headers.get("access-control-max-age") or \
              r.headers.get("Access-Control-Max-Age") or ""
    allow_origin = r.headers.get("access-control-allow-origin") or ""
    allow_methods = r.headers.get("access-control-allow-methods") or ""

    findings = []
    if not max_age:
        # No A-C-Max-Age = browser uses default (5 seconds Chrome, 24h Firefox)
        if allow_origin:
            findings.append(wrap_finding(
                "CORS preflight has no Access-Control-Max-Age",
                "INFO", cwe="CWE-732",
                remediation="Browsers cache preflights using default (5s Chrome, "
                            "24h Firefox). For high-traffic APIs add a deliberate "
                            "max-age (e.g. 600 = 10 min) to avoid per-request "
                            "preflights. Don't exceed 24h.",
                evidence_marker=f"OPTIONS / → Allow-Origin: {allow_origin}, no Max-Age"))
        else:
            return standard_response(
                tool="cors_preflight_cache_abuse", target=req.target,
                findings=[wrap_finding(
                    "No CORS allowed origin — preflight rejected",
                    "POSITIVE", cwe="CWE-942",
                    remediation="Maintain.",
                    evidence_marker=f"OPTIONS / → no Access-Control-Allow-Origin")],
                tests_performed=1, vulnerable=False,
                tests_summary="CORS rejected")
    else:
        try:
            ma = int(max_age)
        except ValueError:
            ma = 0
        if ma > 86400:  # > 24h
            sev = "MEDIUM" if ma > 604800 else "LOW"
            cvss = "5.3" if sev == "MEDIUM" else "3.5"
            findings.append(wrap_finding(
                f"Access-Control-Max-Age={ma}s — preflight cached too long",
                sev, cvss=cvss, cwe="CWE-732", owasp="A05:2021",
                remediation="Cap Access-Control-Max-Age at 86400 (24h). Long max-age "
                            "means CORS-policy changes can't take effect for that "
                            "duration — attacker can keep abusing old permissive "
                            "policy. Browsers also clamp; Chrome caps at 2h, Firefox "
                            "at 24h. Anything over 86400 is dead bytes anyway.",
                evidence_marker=f"OPTIONS / → Access-Control-Max-Age: {max_age}"))
        elif ma > 7200:
            findings.append(wrap_finding(
                f"Access-Control-Max-Age={ma}s — over Chrome's 2h cap (still works in FF/Safari)",
                "INFO", cwe="CWE-732",
                remediation="Cap at 7200 (2h) for cross-browser consistency.",
                evidence_marker=f"Access-Control-Max-Age: {max_age}"))
        else:
            findings.append(wrap_finding(
                f"CORS preflight cache age sensible ({ma}s)",
                "POSITIVE", cwe="CWE-732",
                remediation="Maintain.",
                evidence_marker=f"Access-Control-Max-Age: {ma}s"))

    return standard_response(
        tool="cors_preflight_cache_abuse", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=any(f.get("severity") in ("HIGH", "MEDIUM") for f in findings),
        tests_summary=f"Max-Age: {max_age or 'none'}, Allow-Origin: {allow_origin}",
        raw_data={"max_age": max_age, "allow_origin": allow_origin,
                   "allow_methods": allow_methods})


def register(app):
    app.include_router(router)
