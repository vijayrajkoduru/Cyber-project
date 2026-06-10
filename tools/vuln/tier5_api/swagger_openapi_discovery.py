"""Swagger/OpenAPI spec exposure + shadow-API inventory. VL-FORGE Vuln tier5 - §5 #69/#71.

VL-VERIFY: existing content gate requires `"swagger"` / `"openapi"` / `"paths"`
substrings, which is JSON-specific. Add SPA canary so an SPA shell that
happens to contain `"paths":` in inlined React Router config doesn't
falsely flag as an exposed spec.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get, detect_spa_catchall, is_same_as_canary

router = APIRouter()
_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
          "/swagger-ui.html", "/swagger/v1/swagger.json", "/api/swagger.json",
          "/api/openapi.json", "/.well-known/openapi.json"]


async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    # VL-VERIFY canary baseline
    spa = await detect_spa_catchall(base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    canary_body = spa.get("canary_body", "")

    async def _c(p):
        r = await asyncio.to_thread(http_get, base + p, 8, 4000)
        if not (r and r.get("status") == 200):
            return None
        b = r.get("body", "")
        # SPA catch-all -> drop
        if spa.get("is_spa") and is_same_as_canary(b, canary_body):
            return None
        # Real OpenAPI spec must have either explicit swagger/openapi version
        # field, or a JSON `"paths":` object with `"/"` route keys.
        if '"swagger"' in b or '"openapi"' in b:
            return p
        # Stricter `paths` check: must be a JSON key followed by an object
        # with a route key (real specs have routes starting with `/`).
        if '"paths"' in b and ('":{"/' in b or '": {\n  "/' in b or '":\n  {"/' in b):
            return p
        return None

    res = await asyncio.gather(*[_c(p) for p in _PATHS])
    ctx.source("http")
    ctx.state["tested"] = len(_PATHS)
    found = [p for p in res if p]
    if found:
        ctx.state["specs"] = found


def _r_spec(s):
    sp = s.get("specs") or []
    if not sp:
        return None
    return {"name": f"API spec exposed publicly ({len(sp)})", "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-200",
            "evidence": f"Reachable: {', '.join(sp[:5])} - full API surface (incl. shadow/zombie endpoints) disclosed",
            "remediation": "Restrict Swagger/OpenAPI to internal/authenticated access; remove from production."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("specs"):
        return None
    return {"name": "No public API spec exposed", "severity": "POSITIVE",
            "evidence": "No Swagger/OpenAPI doc reachable on common paths."}


FINDING_RULES = [_r_spec, _r_clean]
INTEL_FIELDS = [("Exposed specs", "specs")]


@router.post("/api/vuln/swagger_openapi_discovery")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="swagger_openapi_discovery",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
