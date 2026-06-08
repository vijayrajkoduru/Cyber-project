"""Multi-role privesc - passive role-enum endpoint check. Self-contained.
Strategy: probe common role/permission endpoints to detect if they expose role names
without auth (info leak that aids privesc). True multi-role testing requires auth."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get

router = APIRouter()

ROLE_PATHS = [
    "/api/roles", "/api/permissions", "/api/v1/roles", "/api/v1/permissions",
    "/roles", "/permissions", "/api/users/me/roles",
]
ROLE_KEYWORDS = ["admin", "superuser", "root", "operator", "owner", "moderator"]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_paths"] = len(ROLE_PATHS)
    leaks = []
    for path in ROLE_PATHS:
        url = f"{base_url}{path}"
        r = http_get(url, timeout=6, read=12000)
        if not r or r.get("status") != 200:
            continue
        body_lower = r.get("body", "").lower()
        matched = [k for k in ROLE_KEYWORDS if k in body_lower]
        if matched:
            leaks.append({"path": path, "roles_seen": matched})
    ctx.state["role_endpoint_leaks"] = leaks


def _r_priv(s):
    leaks = s.get("role_endpoint_leaks") or []
    if not leaks:
        return None
    return {"name": f"{len(leaks)} role/permission endpoint(s) leak role names without auth",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-200",
            "evidence": "; ".join(f"{l['path']} -> {l['roles_seen']}" for l in leaks),
            "remediation": "Require authentication on role/permission discovery endpoints. Don't expose internal role taxonomy publicly."}


FINDING_RULES = [_r_priv]
INTEL_FIELDS = [("Paths probed", "probed_paths"), ("Role leaks", "role_endpoint_leaks")]


@router.post("/api/vuln/multirole_privesc")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="multirole_privesc",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
