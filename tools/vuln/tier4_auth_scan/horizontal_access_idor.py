"""Horizontal access (IDOR) - passive numeric-ID enumeration surface check. Self-contained.
Strategy: requires auth to fully test, so we detect IDOR-PRONE PATTERNS only - URLs
exposing /users/1 /orders/1 /items/1 style and check if /users/2 returns 200 publicly."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

ID_PATHS = [
    "/users/1", "/user/1", "/api/users/1", "/api/v1/users/1",
    "/orders/1", "/api/orders/1",
    "/items/1", "/products/1", "/api/products/1",
    "/posts/1", "/articles/1",
    "/accounts/1",
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
    ctx.state["probed_paths"] = len(ID_PATHS)
    suspect = []
    for path in ID_PATHS:
        # Test id=1 and id=2 - if both return same status 200 with different bodies, IDOR surface
        r1 = await http_get_async(f"{base_url}{path}", timeout=6, read=12000)
        r2 = await http_get_async(f"{base_url}{path[:-1]}2", timeout=6, read=12000)
        if not r1 or not r2:
            continue
        s1, s2 = r1.get("status"), r2.get("status")
        # Both 200 unauthenticated = anyone can enumerate
        if s1 == 200 and s2 == 200:
            b1 = r1.get("body", "")[:500]
            b2 = r2.get("body", "")[:500]
            # Bodies differ = different records returned without auth
            if b1 != b2 and len(b1) > 50 and len(b2) > 50:
                suspect.append({"path": path, "evidence": "id=1 and id=2 return different 200 bodies without auth"})
    ctx.state["idor_suspects"] = suspect


def _r_idor(s):
    sus = s.get("idor_suspects") or []
    if not sus:
        return None
    return {"name": f"{len(sus)} endpoint(s) expose object data by ID without authentication",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-639",
            "evidence": "; ".join(f"{p['path']}" for p in sus),
            "remediation": "Require authentication + per-object authorisation on every resource access. Replace sequential IDs with UUIDs or hashed IDs as defence in depth."}


FINDING_RULES = [_r_idor]
INTEL_FIELDS = [("Paths probed", "probed_paths"), ("IDOR suspects", "idor_suspects")]


@router.post("/api/vuln/horizontal_access_idor")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="horizontal_access_idor",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
