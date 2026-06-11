"""Webapp: Forced browsing - find admin/restricted paths reachable without auth."""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()

# Admin/restricted paths that should require authentication
_ADMIN_PATHS = [
    "/admin","/admin/","/administrator","/wp-admin","/cms/admin","/cpanel",
    "/admin/users","/admin/settings","/admin/config","/admin/dashboard",
    "/admin/console","/admin/login","/admin/panel",
    "/api/admin","/api/admin/users","/api/internal","/api/private",
    "/manager","/manager/html","/management","/dashboard","/console",
    "/phpmyadmin","/pma","/mysql","/db",
    "/.env","/.git/HEAD","/.git/config",
    "/server-status","/server-info","/manage","/private","/internal",
    "/debug","/api/debug","/_debug","/test","/staging",
]

# Heuristic: a "real" reachable admin page contains these markers
_AUTH_MARKERS = re.compile(r"(?:dashboard|admin\s*panel|control\s*panel|console|management|users\s*list|configuration|settings)", re.I)
_LOGIN_REDIRECT = re.compile(r"(?:login|sign[\s-]?in|authenticat)", re.I)


@router.post("/api/webapp/forced_browsing")
@vl_verify()
async def webapp_forced_browsing(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    accessible = []
    import secrets as _sec
    bnonce = "/__vl404_" + _sec.token_hex(8) + ".nope"
    br = safe_get(base + bnonce, req=req, allow_redirects=False, timeout=6)
    spa_baseline = None
    if br is not None and br.status_code == 200 and len(br.content) > 30:
        spa_baseline = {"size": len(br.content), "head": (br.text or "")[:300]}

    
    tests += len(_ADMIN_PATHS)

    async def _probe(path):
        r = await asyncio.to_thread(safe_get, base + path, req=req, allow_redirects=False, timeout=6)
        return (path, r)

    results = await asyncio.gather(
        *[_probe(path) for path in _ADMIN_PATHS],
        return_exceptions=True)
    for res in results:
        if isinstance(res, BaseException) or res is None:
            continue
        path, r = res
        if r is None:
            continue
        if spa_baseline and r.status_code == 200 and abs(len(r.content) - spa_baseline["size"]) < 50 and (r.text or "")[:300] == spa_baseline["head"]:
            continue
        if r.status_code in (401, 403, 407):
            continue  # properly protected
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if _LOGIN_REDIRECT.search(loc):
                continue  # redirected to login, properly protected
        if r.status_code != 200:
            continue
        body = (r.text or "")[:30000]
        # Heuristic: response looks like an admin/restricted page (not a generic 404 or login form)
        has_login_form = bool(re.search(r'<input[^>]*type=["\']?password', body, re.I))
        has_admin_marker = bool(_AUTH_MARKERS.search(body[:5000]))
        if has_login_form and not has_admin_marker:
            continue  # it's a login page, not the admin interface itself
        # Skip if it's an obvious 404 page returned with 200
        if "404" in body[:500] and "not found" in body[:500].lower():
            continue
        if not has_admin_marker and len(body) < 500:
            continue  # too small to be a real admin page
        accessible.append({"path": path, "size": len(r.content), "has_admin_marker": has_admin_marker})
        findings.append(wrap_finding(
            f"Forced browsing - {path} accessible without authentication",
            "HIGH" if has_admin_marker else "MEDIUM",
            cvss="7.5" if has_admin_marker else "5.3",
            cwe="CWE-425",
            cwe_name="Direct Request (Forced Browsing)",
            owasp="A01:2021",
            remediation=("Enforce authentication and authorization checks at the route handler. "
                         "Don't rely on UI hiding alone. For static admin assets, place them behind "
                         "auth middleware or in a non-public directory."),
            evidence_marker=f"GET {path} returned HTTP 200 ({len(r.content)} bytes) - " +
                            ("contains admin-page markers" if has_admin_marker else "no login redirect"),
        ))

    return standard_response(
        tool="forced_browsing", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Probed {tests} restricted paths; {len(accessible)} reachable without auth",
        raw_data={"forced_browsing": {"accessible": accessible}},
    )


def register(app):
    app.include_router(router)
