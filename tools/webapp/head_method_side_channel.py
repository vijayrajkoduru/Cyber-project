"""head_method_side_channel — HEAD request side-channel detection.

Some apps short-circuit HEAD requests early (returning only headers, not
running auth check) → attacker uses HEAD to leak whether resource exists
or to bypass auth-gated endpoints that DO honor GET auth but skip HEAD.

Test: GET /admin → 401/403. HEAD /admin → 200 == BUG.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

PROTECTED_PATHS = ["/admin", "/admin/", "/api/admin", "/api/users",
                    "/dashboard", "/profile", "/.git/config", "/.env"]


@router.post("/api/webapp/scan/head_method_side_channel")
def scan_head_method_side_channel(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    bypasses = []
    tested = 0

    for path in PROTECTED_PATHS:
        url = base + path
        # GET baseline
        r_get = safe_request("GET", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r_get is None or r_get.status_code == 404: continue
        tested += 1
        get_status = r_get.status_code

        # HEAD probe
        r_head = safe_request("HEAD", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r_head is None: continue
        head_status = r_head.status_code

        # Bypass signal: GET 401/403 but HEAD 200
        if get_status in (401, 403) and head_status == 200:
            bypasses.append({"path": path, "get_status": get_status,
                              "head_status": head_status})
        # Information leak: HEAD reveals more than GET (200 on HEAD where GET is 404)
        elif get_status == 404 and head_status == 200:
            bypasses.append({"path": path, "get_status": get_status,
                              "head_status": head_status,
                              "issue": "HEAD-leaks-existence"})

    findings = []
    if bypasses:
        findings.append(wrap_finding(
            f"HEAD method side-channel at {len(bypasses)} path(s)",
            "HIGH", cvss="7.5", cwe="CWE-200", owasp="A01:2021",
            remediation="HEAD should behave identically to GET (RFC 9110 §9.3.2). "
                        "Auth middleware must run on HEAD too. Most frameworks "
                        "handle this — bug is usually in custom routing or static-"
                        "file serving (nginx 'autoindex' on, etc.). Add explicit "
                        "HEAD handlers OR configure server to return 405 if HEAD "
                        "is unhandled. Don't let HEAD bypass auth.",
            evidence_marker=" | ".join(
                f"{b['path']}: GET={b['get_status']} HEAD={b['head_status']}"
                for b in bypasses[:5]
            )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"HEAD method behaves consistently with GET ({tested} paths)",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. Continue testing new endpoints for HEAD/GET parity.",
            evidence_marker=f"{tested} protected paths tested, 0 bypasses"))
    else:
        return standard_response(
            tool="head_method_side_channel", target=req.target, findings=[],
            tests_performed=len(PROTECTED_PATHS), vulnerable=False,
            skipped_reason="No protected paths reachable on target")

    return standard_response(
        tool="head_method_side_channel", target=req.target, findings=findings,
        tests_performed=len(PROTECTED_PATHS) * 2,
        vulnerable=bool(bypasses),
        tests_summary=f"{tested} paths tested, {len(bypasses)} HEAD bypasses",
        raw_data={"bypasses": bypasses})


def register(app):
    app.include_router(router)
