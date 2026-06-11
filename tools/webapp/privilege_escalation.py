"""Webapp: Vertical privilege escalation via header / role manipulation."""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
from tools._vl_core.verify import vl_verify

router = APIRouter()

_ADMIN_PATHS = ["/admin","/admin/users","/admin/dashboard","/admin/settings","/api/admin","/api/admin/users","/api/internal","/api/private"]
_AUTH_BYPASS_HEADERS = [
    {"X-User-Role": "admin"},
    {"X-Auth-Role": "admin"},
    {"X-Forwarded-User": "admin"},
    {"X-Original-User": "admin"},
    {"X-Custom-Auth": "admin"},
    {"X-Authenticated-User": "admin"},
]


@router.post("/api/webapp/privilege_escalation")
@vl_verify()
async def webapp_privilege_escalation(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    tests = 0
    suspect = []
    spa_suppressed = []

    # Stage 1: fetch baselines for all paths in parallel
    async def _baseline(path):
        b = await asyncio.to_thread(safe_get, base + path, req=req, allow_redirects=False, timeout=6)
        return (path, b)

    baseline_results = await asyncio.gather(
        *[_baseline(path) for path in _ADMIN_PATHS],
        return_exceptions=True)
    tests += len(_ADMIN_PATHS)

    # Stage 2: for each path with a blocking baseline, fan-out bypass-header probes
    async def _probe_headers(path, b_status):
        def _get(hdr):
            try:
                return requests.get(base + path, headers={**hdr, "User-Agent":"VulnusLab/1.0"},
                                    timeout=6, allow_redirects=False, verify=False)
            except Exception:
                return None
        rs = await asyncio.gather(
            *[asyncio.to_thread(_get, hdr) for hdr in _AUTH_BYPASS_HEADERS],
            return_exceptions=True)
        # Preserve original break-on-first-hit ordering
        for hdr, r in zip(_AUTH_BYPASS_HEADERS, rs):
            if isinstance(r, BaseException) or r is None:
                continue
            if r.status_code == 200 and len(r.content) > 200:
                return (path, b_status, hdr, r)
        return None

    probe_jobs = []
    for bres in baseline_results:
        if isinstance(bres, BaseException) or bres is None:
            continue
        path, baseline = bres
        if baseline is None:
            continue
        if spa["is_spa"] and baseline.status_code == 200 and \
           is_same_as_canary(baseline.text or "", spa["canary_body"]):
            spa_suppressed.append(path)
            continue
        if baseline.status_code in (200, 302):
            continue
        if baseline.status_code not in (401, 403, 404):
            continue
        probe_jobs.append((path, baseline.status_code))

    tests += len(probe_jobs) * len(_AUTH_BYPASS_HEADERS)
    probe_results = await asyncio.gather(
        *[_probe_headers(path, b_status) for path, b_status in probe_jobs],
        return_exceptions=True)
    for pres in probe_results:
        if isinstance(pres, BaseException) or pres is None:
            continue
        path, b_status, hdr, r = pres
        hdr_name = list(hdr.keys())[0]
        suspect.append({"path": path, "header": hdr_name, "baseline_status": b_status, "bypass_status": 200})
        findings.append(wrap_finding(
            f"Privilege escalation - {hdr_name} header bypasses access control on {path}",
            "CRITICAL",
            cvss="9.8", cwe="CWE-285",
            cwe_name="Improper Authorization",
            owasp="A01:2021",
            remediation=("Never trust user-controllable headers for authorization. Derive the "
                         "user's role from a server-validated session/JWT, not from request "
                         "headers. If a reverse proxy injects auth headers, strip them at "
                         "the proxy before passing to the application."),
            evidence_marker=f"GET {path} baseline {b_status}; GET {path} with '{hdr_name}: admin' -> 200 ({len(r.content)} bytes)",
        ))

    return standard_response(
        tool="privilege_escalation", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Tested {len(_ADMIN_PATHS)} admin paths against {len(_AUTH_BYPASS_HEADERS)} bypass headers",
        raw_data={"privilege_escalation": {"suspect": suspect,
                                              "spa_catchall": spa["is_spa"],
                                              "spa_suppressed_paths": spa_suppressed}},
    )


def register(app):
    app.include_router(router)
