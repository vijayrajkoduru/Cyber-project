"""server_timing_leak — Server-Timing / X-* header leaks backend internals.

Server-Timing exposes backend latency breakdowns (good for debugging,
bad in production). X-Powered-By / X-AspNet-Version / X-Backend leak
stack/version info that helps attackers pick exploit chains.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

LEAKY_HEADERS = [
    ("server-timing",            "Backend timing telemetry exposed"),
    ("x-powered-by",             "Server stack disclosed (e.g. PHP/8.1)"),
    ("x-aspnet-version",         "ASP.NET version disclosed"),
    ("x-aspnetmvc-version",      "ASP.NET MVC version disclosed"),
    ("x-runtime",                "App runtime + version disclosed"),
    ("x-backend",                "Backend server identifier disclosed"),
    ("x-backend-server",         "Backend server identifier disclosed"),
    ("x-debug-token",            "Symfony debug toolbar token (DEV mode)"),
    ("x-debug-token-link",       "Symfony debug toolbar URL (DEV mode)"),
    ("x-version",                "App version disclosed"),
    ("x-app-version",            "App version disclosed"),
    ("x-served-by",              "Origin server identifier (cache pivot)"),
    ("x-cache-hits",             "Cache hit count (deanon timing)"),
    ("x-django-debug",           "Django DEBUG mode active"),
    ("x-drupal-cache",           "Drupal cache state disclosed"),
    ("x-generator",              "CMS/framework identifier"),
]


@router.post("/api/webapp/scan/server_timing_leak")
@vl_turbo()
def scan_server_timing_leak(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="server_timing_leak", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No response from target")

    # Normalize headers (case-insensitive)
    hdrs = {k.lower(): v for k, v in r.headers.items()}

    leaks = []
    debug_mode = False
    for name, desc in LEAKY_HEADERS:
        if name in hdrs:
            val = hdrs[name][:120]
            leaks.append({"header": name, "value": val, "desc": desc})
            if "debug" in name.lower():
                debug_mode = True

    # Server header — generic but often leaks
    if "server" in hdrs:
        server = hdrs["server"]
        if any(t in server for t in ("/", "-")) and len(server) > 4:
            # Likely contains version: nginx/1.18.0, Apache/2.4.41
            leaks.append({"header": "server", "value": server[:80],
                          "desc": "Server software + version disclosed"})

    findings = []
    if debug_mode:
        findings.append(wrap_finding(
            "DEBUG-mode headers detected — staging config in production",
            "HIGH", cvss="7.5", cwe="CWE-489", owasp="A05:2021",
            remediation="Switch to production config: APP_DEBUG=false (Symfony/"
                        "Laravel), DEBUG=False (Django), NODE_ENV=production. "
                        "Debug mode leaks stack traces + secrets to ANY request.",
            evidence_marker=" | ".join(f"{l['header']}: {l['value']}" for l in leaks
                                          if "debug" in l["header"].lower())))

    if leaks and not debug_mode:
        sev = "LOW"
        cvss = "3.5"
        # If Server-Timing leaks specific backend names, bump to MEDIUM
        if any(l["header"] == "server-timing" and len(l["value"]) > 40 for l in leaks):
            sev = "MEDIUM"; cvss = "5.3"
        findings.append(wrap_finding(
            f"Information-disclosure headers ({len(leaks)})",
            sev, cvss=cvss, cwe="CWE-200", owasp="A05:2021",
            remediation="Strip leaky headers at the reverse proxy: "
                        "nginx: `more_clear_headers 'X-Powered-By' 'X-AspNet-Version' "
                        "'Server-Timing';`; Apache: `Header unset X-Powered-By`. "
                        "Or at the app: Spring `server.error.include-message=never`; "
                        "Express `app.disable('x-powered-by')`. Server-Timing in "
                        "particular helps timing attacks + reveals internal service "
                        "names.",
            evidence_marker=" | ".join(f"{l['header']}: {l['value']}" for l in leaks[:8])))

    if not findings:
        findings.append(wrap_finding(
            f"No information-disclosure headers detected",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. Keep stripping headers at the edge.",
            evidence_marker=f"checked {len(LEAKY_HEADERS) + 1} known-leaky header names"))

    return standard_response(
        tool="server_timing_leak", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(leaks),
        tests_summary=f"{len(leaks)} leaky headers, debug_mode: {debug_mode}",
        raw_data={"leaks": leaks, "debug_mode": debug_mode})


def register(app):
    app.include_router(router)
