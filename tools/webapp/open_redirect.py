"""Open Redirect scanner.

Zero-FP via Location-header confirmation. Inject attacker-controlled
URL into each parameter, verify Location header points to canary host.

9 bypass variants (absolute, protocol-relative, backslash, no-slashes,
URL-encoded, userinfo trick, subdomain trick).
"""
import urllib.parse
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url, recon_host,
    safe_get, wrap_finding, standard_response,
)

router = APIRouter()

CANARY_HOST = "evil-attacker.example"


def _inject_param(url, param, value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))


def _payloads_for(target_host):
    return [
        ("absolute https",        f"https://{CANARY_HOST}/poison"),
        ("absolute http",         f"http://{CANARY_HOST}/poison"),
        ("protocol-relative //",  f"//{CANARY_HOST}/poison"),
        ("backslash",             f"\\\\{CANARY_HOST}/poison"),
        ("https no slashes",      f"https:{CANARY_HOST}/poison"),
        ("URL-encoded https",     f"https%3A%2F%2F{CANARY_HOST}%2Fpoison"),
        ("URL-encoded //",        f"%2F%2F{CANARY_HOST}%2Fpoison"),
        ("userinfo trick",        f"https://{target_host}@{CANARY_HOST}/poison"),
        ("subdomain trick",       f"https://{target_host}.{CANARY_HOST}/poison"),
    ]


def _location_matches_canary(location):
    if not location:
        return False
    try:
        loc = "https:" + location if location.startswith("//") else location
        loc = loc.replace("\\", "/")
        parsed = urllib.parse.urlparse(loc)
        hostname = (parsed.hostname or "").lower()
        return CANARY_HOST in hostname
    except Exception:
        return False


@router.post("/api/scan/open_redirect")
async def scan_open_redirect(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    tests = 0
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if not qs:
        return standard_response(
            tool="open_redirect", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters present — append ?next=/home (or similar) to test",
        )

    target_host = recon_host(req.target)
    payloads = _payloads_for(target_host)
    raw_results = []

    for param, _orig in qs.items():
        tests += 1
        confirmed = None
        for variant, payload in payloads:
            test_url = _inject_param(url, param, payload)
            r = safe_get(test_url, req=req, allow_redirects=False, timeout=10)
            if r is None or r.status_code not in (301, 302, 303, 307, 308):
                continue
            location = r.headers.get("Location", "")
            if _location_matches_canary(location):
                confirmed = {"variant": variant, "payload": payload,
                             "status_code": r.status_code, "location": location[:200]}
                break

        if confirmed:
            findings.append(wrap_finding(
                f"Open Redirect in parameter '{param}'",
                "HIGH", cwe="CWE-601", owasp="A01:2021",
                evidence_marker=f"payload `{confirmed['payload']}` returned HTTP {confirmed['status_code']} Location: {confirmed['location']} ({confirmed['variant']})",
                remediation="Validate redirect targets against an allow-list of permitted destinations. Reject anything not on the application's own domain. Never pass user-supplied parameters straight to a redirect.",
                tests_performed=1,
                cvss="6.1",
            ))
            raw_results.append({"param": param, "result": "VULNERABLE", **confirmed})
        else:
            raw_results.append({"param": param, "result": "safe"})

    return standard_response(
        tool="open_redirect", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Tested {tests} parameter(s) with {len(payloads)} bypass variants each",
        raw_data={"open_redirect": {"params_tested": tests, "vulnerable_count": len(findings), "results": raw_results}},
    )


def register(app):
    app.include_router(router)
