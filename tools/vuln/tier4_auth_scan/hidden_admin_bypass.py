"""Hidden admin panel discovery - passive 200-without-auth detection. Self-contained.
Strategy: probe common admin paths, flag ones returning 200 OK or 302-to-non-login."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get

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
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_paths"] = len(ADMIN_PATHS)
    exposed = []
    auth_required = []
    for path in ADMIN_PATHS:
        url = f"{base_url}{path}"
        r = http_get(url, timeout=6, read=8000)
        if not r:
            continue
        status = r.get("status", 0)
        body_lower = r.get("body", "").lower()
        # 200 with admin keywords + no login form = exposed
        if status == 200:
            has_admin_words = any(w in body_lower for w in ["admin", "dashboard", "manage", "console"])
            has_login = any(w in body_lower for w in ["password", "login", "sign in", "<input type=\"password"])
            if has_admin_words and not has_login:
                exposed.append({"path": path, "status": 200, "evidence": "200 OK without login form"})
            elif has_admin_words and has_login:
                auth_required.append({"path": path, "status": 200})
        elif status in (401, 403):
            auth_required.append({"path": path, "status": status})
    ctx.state["exposed_admin"] = exposed
    ctx.state["protected_admin"] = auth_required


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
    return {"name": f"{len(auth)} admin panel(s) discovered (auth required - good)",
            "severity": "INFO", "cwe": "CWE-200",
            "evidence": "; ".join(f"{a['path']} ({a['status']})" for a in auth),
            "remediation": "Optional: move admin to /a/<random> URL to reduce brute-force surface, restrict by IP/VPN."}


FINDING_RULES = [_r_exposed, _r_protected]
INTEL_FIELDS = [("Paths probed", "probed_paths"), ("Exposed", "exposed_admin"), ("Protected", "protected_admin")]


@router.post("/api/vuln/hidden_admin_bypass")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="hidden_admin_bypass",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
