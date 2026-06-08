"""A07 Identification & Auth Failures - passive cookie/login-page hygiene check. Self-contained.
Strategy: hit common login paths, inspect Set-Cookie attrs + form action + autocomplete attrs."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get

router = APIRouter()

LOGIN_PATHS = ["/login", "/signin", "/account/login", "/user/login", "/admin/login", "/wp-login.php"]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    issues = []
    login_found = []
    for path in LOGIN_PATHS:
        url = f"{base_url}{path}"
        r = http_get(url, timeout=8, read=20000)
        if not r or r.get("status", 0) >= 400:
            continue
        body_lower = r.get("body", "").lower()
        if "<form" not in body_lower and "password" not in body_lower:
            continue
        login_found.append(path)
        # Form over HTTP (no TLS)
        if url.startswith("http://"):
            issues.append({"path": path, "issue": "Login form served over plain HTTP", "sev": "HIGH"})
        # Set-Cookie missing Secure/HttpOnly
        sc = r.get("headers", {}).get("set-cookie", "") or ""
        if sc:
            if "secure" not in sc.lower():
                issues.append({"path": path, "issue": "Session cookie without Secure flag", "sev": "MEDIUM"})
            if "httponly" not in sc.lower():
                issues.append({"path": path, "issue": "Session cookie without HttpOnly flag", "sev": "MEDIUM"})
            if "samesite" not in sc.lower():
                issues.append({"path": path, "issue": "Session cookie without SameSite", "sev": "LOW"})
        # autocomplete="off" missing on password fields
        if 'type="password"' in body_lower and 'autocomplete="off"' not in body_lower and 'autocomplete="new-password"' not in body_lower:
            issues.append({"path": path, "issue": "Password field allows browser autocomplete", "sev": "LOW"})
        break  # only need 1 login page for sampling
    ctx.state["login_paths"] = login_found
    ctx.state["auth_issues"] = issues


def _r_high(s):
    issues = [i for i in (s.get("auth_issues") or []) if i["sev"] == "HIGH"]
    if not issues:
        return None
    return {"name": f"{len(issues)} HIGH auth-hygiene issue(s)", "severity": "HIGH", "cvss": 7.4,
            "cwe": "CWE-319", "evidence": "; ".join(f"{i['path']}: {i['issue']}" for i in issues),
            "remediation": "Serve login over HTTPS only. Enforce HSTS."}


def _r_med(s):
    med = [i for i in (s.get("auth_issues") or []) if i["sev"] in ("MEDIUM", "LOW")]
    if not med:
        return None
    return {"name": f"{len(med)} auth/session hygiene weakness(es)", "severity": "MEDIUM", "cvss": 5.3,
            "cwe": "CWE-614", "evidence": "; ".join(f"{i['path']}: {i['issue']}" for i in med),
            "remediation": "Set Secure, HttpOnly, SameSite=Strict on all session cookies."}


FINDING_RULES = [_r_high, _r_med]
INTEL_FIELDS = [("Login pages found", "login_paths"), ("Auth issues", "auth_issues")]


@router.post("/api/vuln/a07_auth_failures")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a07_auth_failures",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
