"""Broken Access Control — admin paths reachable without admin role."""
import hashlib
import secrets
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

_ADMIN_PATHS = [
    "/rest/admin/application-configuration",
    "/rest/admin/application-version",
    "/api/admin", "/admin", "/admin/dashboard",
    "/api/users", "/api/v1/admin",
    "/rest/user/authentication-details",
    "/api/system/info", "/api/v1/system",
    "/management", "/actuator", "/actuator/env",
    "/admin/config", "/manage", "/console",
]


def _fp(r):
    body = (r.text or "")[:2000]
    return f"{r.status_code}:{hashlib.md5(body.encode('utf-8', errors='ignore')).hexdigest()}"


@router.post("/api/webapp/scan/access_control")
@vl_turbo()
@vl_verify()
def scan_access_control(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    has_auth = bool(getattr(req, "auth_cookie", None) or getattr(req, "auth_bearer", None))
    spa = load_spa_state(req.target)
    paths = list(_ADMIN_PATHS)
    for url in (spa.get("urls") or []) + list((spa.get("endpoints") or {}).keys()):
        low = url.lower()
        if any(k in low for k in ("admin", "manage", "actuator")):
            path = url.replace(base, "") or url
            if path.startswith("/") and path not in paths:
                paths.append(path)

    # SPA-shell baseline so we don't fire on every 200-everywhere SPA
    canary = "/_vl_canary_" + secrets.token_hex(6) + "_bac"
    canary_r = safe_get(base + canary, req=req, allow_redirects=False, timeout=8)
    canary_fp = _fp(canary_r) if canary_r is not None else None
    spa_shell = canary_r is not None and canary_r.status_code == 200

    findings, tests, confirmed = [], 0, []
    for path in paths[:20]:
        tests += 1
        r = safe_get(base + path if path.startswith("/") else f"{base}/{path}",
                      req=req, allow_redirects=False, timeout=8)
        if r is None or r.status_code != 200:
            continue
        if spa_shell and _fp(r) == canary_fp:
            continue
        text = (r.text or "")[:5000].lower()
        is_admin_resp = any(m in text for m in (
            "applicationversion", "application_version",
            "\"users\"", "authentication", "configuration"))
        if is_admin_resp and len(r.text or "") > 100:
            sev = "CRITICAL" if has_auth else "HIGH"
            findings.append(wrap_finding(
                f"Broken Access Control — {path} returns admin/sensitive data"
                f"{' as authenticated non-admin user' if has_auth else ' without authentication'}",
                sev, cvss="8.6", cwe="CWE-284", owasp="A01:2021",
                remediation=("Add role-based access control. Verify the requesting "
                           "user has the required role before returning the data; "
                           "return 403 otherwise."),
                evidence_marker=f"GET {path} returned 200 with admin-sensitive content"))
            confirmed.append({"path": path, "status": r.status_code,
                              "len": len(r.content)})

    return standard_response(tool="access_control", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Access Control: {tests} admin/internal paths probed (auth={'on' if has_auth else 'off'})",
        raw_data={"access_control": {"confirmed": confirmed,
                                       "spa_shell_baseline": spa_shell}})


def register(app):
    app.include_router(router)
