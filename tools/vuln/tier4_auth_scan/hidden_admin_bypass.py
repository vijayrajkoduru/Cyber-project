"""Hidden admin panel discovery - passive 200-without-auth detection. Self-contained.
Strategy: probe common admin paths, flag ones returning 200 OK or 302-to-non-login.

VL-VERIFY: existing content-word gates ("admin"/"dashboard"/"manage"/"console"
in body, no login form) already filter most SPA FPs, but SPA shells whose
title contains "Dashboard" (e.g. analytics dashboards) can leak through.
Belt-and-braces canary check ensures no SPA catch-all response is flagged.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, detect_spa_catchall, is_same_as_canary
from tools._vl_core.verify import vl_verify

router = APIRouter()

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin.php", "/admin/index.php",
    "/wp-admin/", "/wp-admin", "/dashboard", "/manager", "/manage",
    "/portal", "/console", "/control", "/cpanel",
    "/api/admin", "/api/v1/admin", "/admin/api",
    "/phpmyadmin", "/pma", "/db", "/database",
    "/server-manager", "/jenkins", "/grafana", "/kibana",
]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_paths"] = len(ADMIN_PATHS)
    # VL-VERIFY canary — fired once so we can reject 200 responses that
    # match the SPA shell verbatim, even if the shell happens to contain
    # "dashboard" / "admin" words.
    spa = await detect_spa_catchall(base_url)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    canary_body = spa.get("canary_body", "")
    exposed = []
    auth_protected = []   # 401/403 - confirmed auth required
    login_page = []       # 200 with login form - likely safe but verify
    for path in ADMIN_PATHS:
        url = f"{base_url}{path}"
        r = await http_get_async(url, timeout=6, read=8000)
        if not r:
            continue
        status = r.get("status", 0)
        body = r.get("body", "")
        body_lower = body.lower()
        if status == 200:
            # Reject SPA catch-all — same body as the bogus canary path
            if spa.get("is_spa") and is_same_as_canary(body, canary_body):
                continue
            has_admin_words = any(w in body_lower for w in ["admin", "dashboard", "manage", "console"])
            has_login = any(w in body_lower for w in ["password", "login", "sign in", "<input type=\"password"])
            if has_admin_words and not has_login:
                exposed.append({"path": path, "status": 200, "evidence": "200 OK without login form"})
            elif has_admin_words and has_login:
                login_page.append({"path": path, "status": 200})
        elif status in (401, 403):
            auth_protected.append({"path": path, "status": status})
    ctx.state["exposed_admin"] = exposed
    # Keep auth-protected (401/403) separate from "200 with login form" - the
    # latter only LOOKS auth-required but a 200 response code doesn't actually
    # prove auth enforcement. Per user feedback 2026-06-09: don't claim
    # "auth required - good" on 200 responses that share scope with paths
    # other scanners (vertical_access_admin) confirmed as exposed.
    ctx.state["protected_admin"] = auth_protected
    ctx.state["login_page_admin"] = login_page


def _r_exposed(s):
    exp = s.get("exposed_admin") or []
    if not exp:
        return None
    return {"name": f"{len(exp)} admin path(s) accessible without authentication",
            "severity": "CRITICAL", "cvss": 9.1, "cwe": "CWE-284",
            "evidence": "; ".join(e["path"] for e in exp),
            "remediation": "Require authentication on all admin paths. Block /wp-admin /phpmyadmin etc at WAF if not in use."}


def _r_protected(s):
    auth = s.get("protected_admin") or []
    if not auth:
        return None
    return {"name": f"{len(auth)} admin panel(s) returned 401/403 - auth enforcement confirmed",
            "severity": "INFO", "cwe": "CWE-200",
            "evidence": "; ".join(f"{a['path']} ({a['status']})" for a in auth),
            "remediation": "Optional: move admin to /a/<random> URL to reduce brute-force surface, restrict by IP/VPN."}


def _r_login_page(s):
    pages = s.get("login_page_admin") or []
    if not pages:
        return None
    return {"name": f"{len(pages)} admin path(s) returned 200 with login form - verify auth manually",
            "severity": "INFO", "cwe": "CWE-200",
            "evidence": "; ".join(f"{p['path']} (200)" for p in pages),
            "remediation": "Verify each path actually requires auth (POST a request without credentials). A 200 status alone does not prove auth enforcement."}


FINDING_RULES = [_r_exposed, _r_protected, _r_login_page]
INTEL_FIELDS = [("Paths probed", "probed_paths"), ("Exposed", "exposed_admin"),
                ("Auth-protected (401/403)", "protected_admin"),
                ("Login page (200, verify)", "login_page_admin")]


@router.post("/api/vuln/hidden_admin_bypass")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="hidden_admin_bypass",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
