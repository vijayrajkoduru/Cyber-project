"""broken_function_level_auth — OWASP API #5: regular user reaches admin endpoint.

Probes admin/management endpoints WITH a regular-user token (auth_bearer)
and WITHOUT auth. Vulnerable if regular-user token returns 200 on
admin endpoint (BFLA — Broken Function-Level Authorization).

Customer provides their NON-admin JWT via auth_bearer for this scanner.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/dashboard",
    "/api/admin", "/api/admin/users", "/api/admin/settings",
    "/api/v1/admin", "/api/v1/admin/users",
    "/api/users", "/api/users/all",
    "/api/internal", "/api/management",
    "/management", "/actuator/env", "/actuator/heapdump",
    "/api/admin/audit", "/api/v1/admin/audit",
]


def _probe(url, headers, req):
    return safe_request("GET", url,
        headers={**headers, "User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/broken_function_level_auth")
def scan_broken_function_level_auth(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    token = (req.auth_bearer or "").strip()
    if not token:
        return standard_response(
            tool="broken_function_level_auth", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="No JWT provided. Pass a non-admin user's JWT via "
                            "auth_bearer to test admin-endpoint access controls.")

    bfla_hits = []
    unauth_hits = []
    tested = 0

    for path in ADMIN_PATHS:
        url = base + path

        # Test 1: unauth — should be 401/403/404
        r0 = _probe(url, {}, req)
        if r0 is None: continue
        tested += 1
        unauth_status = r0.status_code
        if unauth_status == 200:
            unauth_hits.append({"path": path, "status": 200})

        # Test 2: as non-admin user — should be 403 if BFLA properly enforced
        r1 = _probe(url, {"Authorization": f"Bearer {token}"}, req)
        if r1 is None: continue
        if r1.status_code == 200:
            # Distinguish "endpoint serves your own data" vs "leaks admin"
            body_low = (r1.text or "")[:5000].lower()
            admin_indicators = ("all users", "user list", "[", "audit", "settings",
                                 "internal", "heap", "env=")
            if any(i in body_low for i in admin_indicators):
                bfla_hits.append({
                    "path": path,
                    "unauth_status": unauth_status,
                    "user_status": 200,
                    "size": len(r1.content) if r1.content else 0,
                })

    findings = []
    if unauth_hits:
        findings.append(wrap_finding(
            f"Admin endpoint(s) accessible WITHOUT AUTH ({len(unauth_hits)})",
            "CRITICAL", cvss="9.8", cwe="CWE-306", owasp="A01:2021",
            remediation="Admin paths return 200 without any auth — full unauthenticated "
                        "admin access. Add authentication middleware GLOBALLY then "
                        "opt-out for public paths. Frameworks: Spring Security "
                        "antMatchers + denyAll default; Django LoginRequiredMiddleware.",
            evidence_marker=" | ".join(f"{h['path']}: HTTP 200" for h in unauth_hits[:5])))

    if bfla_hits:
        findings.append(wrap_finding(
            f"BROKEN function-level auth — regular user reaches admin ({len(bfla_hits)})",
            "CRITICAL", cvss="9.0", cwe="CWE-285", owasp="A01:2021",
            remediation="OWASP API Top 10 #5 — Broken Function Level Authorization. "
                        "Admin endpoint requires ROLE check beyond just 'is authenticated'. "
                        "Implement role-based access control: middleware decorator that "
                        "checks request.user.role == 'admin' BEFORE the resolver runs. "
                        "Default deny: admin = explicit role grant, never implicit.",
            evidence_marker=" | ".join(
                f"{h['path']} (unauth: {h['unauth_status']}, user: 200, "
                f"{h['size']}B body)"
                for h in bfla_hits[:5]
            )))

    if not findings:
        findings.append(wrap_finding(
            f"Admin endpoints properly gated ({tested} tested)",
            "POSITIVE", cwe="CWE-285",
            remediation="Maintain. Add new admin routes with role-check middleware "
                        "default.",
            evidence_marker=f"{tested} admin paths tested with no-auth + user-token"))

    return standard_response(
        tool="broken_function_level_auth", target=req.target, findings=findings,
        tests_performed=tested * 2,
        vulnerable=bool(unauth_hits or bfla_hits),
        tests_summary=f"{tested} admin paths, unauth: {len(unauth_hits)}, BFLA: {len(bfla_hits)}",
        raw_data={"unauth_hits": unauth_hits, "bfla_hits": bfla_hits})


def register(app):
    app.include_router(router)
