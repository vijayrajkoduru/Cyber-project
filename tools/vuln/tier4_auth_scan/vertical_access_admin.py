"""Vertical access (admin endpoint) - passive privileged-action endpoint enumeration.
Self-contained. Strategy: probe destructive/admin-only API paths, check if they return
200 without authentication (full privesc) or 401/403 (auth correctly required)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, http_post_async

router = APIRouter()

# Privileged action endpoints typically requiring admin auth
PRIV_PATHS_GET = ["/api/admin/users", "/api/admin/config", "/admin/api/users",
                    "/api/v1/admin", "/api/system", "/api/internal"]
PRIV_PATHS_POST = ["/api/admin/users", "/api/users"]  # Test if POST creates user without auth


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    exposed = []
    protected = []
    for path in PRIV_PATHS_GET:
        url = f"{base_url}{path}"
        r = await http_get_async(url, timeout=6, read=4000)
        if not r:
            continue
        status = r.get("status", 0)
        if status == 200:
            body = r.get("body", "")[:300]
            if len(body) > 50:
                exposed.append({"method": "GET", "path": path, "evidence": "200 with body"})
        elif status in (401, 403):
            protected.append({"method": "GET", "path": path, "status": status})
    for path in PRIV_PATHS_POST:
        url = f"{base_url}{path}"
        r = await http_post_async(url, data=b'{}', headers={"Content-Type": "application/json"}, timeout=6)
        if not r:
            continue
        status = r.get("status", 0)
        # 401/403 = good. 405 = method not allowed (fine). 200/201 with empty body = bad.
        if status in (200, 201) and r.get("body", "").strip():
            exposed.append({"method": "POST", "path": path, "evidence": f"status {status} on empty body"})
    ctx.state["exposed_privileged"] = exposed
    ctx.state["protected_privileged"] = protected


def _r_exposed(s):
    exp = s.get("exposed_privileged") or []
    if not exp:
        return None
    return {"name": f"{len(exp)} privileged endpoint(s) accessible without authentication",
            "severity": "CRITICAL", "cvss": 9.1, "cwe": "CWE-285",
            "evidence": "; ".join(f"{e['method']} {e['path']}" for e in exp),
            "remediation": "Require authentication AND admin-role authorisation on every /admin and /api/admin path."}


FINDING_RULES = [_r_exposed]
INTEL_FIELDS = [("Exposed privileged", "exposed_privileged"), ("Auth-protected", "protected_privileged")]


@router.post("/api/vuln/vertical_access_admin")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="vertical_access_admin",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
