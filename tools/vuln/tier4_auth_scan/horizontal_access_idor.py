"""Horizontal access (IDOR) - passive numeric-ID enumeration surface check. Self-contained.
Strategy: requires auth to fully test, so we detect IDOR-PRONE PATTERNS only - URLs
exposing /users/1 /orders/1 /items/1 style and check if /users/2 returns 200 publicly."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, detect_spa_catchall, is_same_as_canary
from tools._vl_core.verify import vl_verify

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
    # SPA-detect: SSR React apps (Next.js / Nuxt) can return slightly
    # different shells per route, which would false-positive as IDOR.
    # (User feedback 2026-06-09 SPA-FP audit)
    spa = await detect_spa_catchall(base_url)
    ctx.state["spa_detected"] = spa["is_spa"]
    suspect = []
    spa_suppressed = []
    for path in ID_PATHS:
        r1 = await http_get_async(f"{base_url}{path}", timeout=6, read=12000)
        r2 = await http_get_async(f"{base_url}{path[:-1]}2", timeout=6, read=12000)
        if not r1 or not r2:
            continue
        s1, s2 = r1.get("status"), r2.get("status")
        if s1 == 200 and s2 == 200:
            b1 = r1.get("body", "")[:500]
            b2 = r2.get("body", "")[:500]
            if b1 == b2 or len(b1) <= 50 or len(b2) <= 50:
                continue
            # SPA suppression: if EITHER response matches the SPA canary,
            # we're getting catch-all shells, not real per-ID objects.
            if spa["is_spa"] and (is_same_as_canary(r1.get("body", ""), spa["canary_body"]) or
                                   is_same_as_canary(r2.get("body", ""), spa["canary_body"])):
                spa_suppressed.append({"path": path, "reason": "SPA shell"})
                continue
            # Confidence boost: require JSON content-type. Real IDOR-exposed
            # endpoints return JSON objects, not HTML.
            ctype = (r1.get("headers") or {}).get("content-type", "").lower()
            looks_json = "json" in ctype or b1.lstrip().startswith(("{", "["))
            if not looks_json:
                spa_suppressed.append({"path": path, "reason": "expected JSON, got non-JSON"})
                continue
            suspect.append({"path": path, "evidence": "id=1 and id=2 return different 200 JSON bodies without auth"})
    ctx.state["idor_suspects"] = suspect
    if spa_suppressed:
        ctx.state["spa_suppressed_findings"] = spa_suppressed


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
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="horizontal_access_idor",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
