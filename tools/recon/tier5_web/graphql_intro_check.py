"""GraphQL Introspection Check — VL-FORGE. No endpoint / 404 => clean (no finding)."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router = APIRouter()
PATHS = ["/graphql","/api/graphql","/v1/graphql","/graphql/v1","/query","/gql","/graphiql","/playground"]
INTRO = {"query": "{__schema{queryType{name}}}"}
def _probe(url):
    try:
        r = requests.post(url, json=INTRO, timeout=8,
                          headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"})
    except Exception:
        return None
    if r.status_code >= 400:
        return None
    try:
        j = r.json()
    except Exception:
        return None
    if isinstance(j, dict) and isinstance(j.get("data"), dict) and j["data"].get("__schema"):
        return {"url": url, "introspection": True}
    if isinstance(j, dict) and ("data" in j or "errors" in j):
        return {"url": url, "introspection": False}
    return None
async def gather(ctx):
    h = str(ctx.host)
    base = h if h.startswith("http") else "https://" + h
    urls = [base.rstrip("/") + p for p in PATHS]
    res = await asyncio.gather(*[asyncio.to_thread(_probe, u) for u in urls])
    hits = [x for x in res if x]
    ctx.source("probed-%d-paths" % len(urls))
    ctx.state.update({
        "graphql_endpoints": [x["url"] for x in hits],
        "introspection_enabled": [x["url"] for x in hits if x["introspection"]],
        "endpoint_count": len(hits),
    })
def _r_intro(s):
    ex = s.get("introspection_enabled") or []
    if not ex:
        return None
    return {"name": "GraphQL introspection enabled on %d endpoint(s)" % len(ex),
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-200", "owasp": "API3:2023",
            "evidence": "Introspection __schema exposed: " + ", ".join(ex[:5]),
            "remediation": "Disable GraphQL introspection in production (introspection:false / NODE_ENV=production)."}
def _r_found(s):
    found = s.get("graphql_endpoints") or []
    if not found or (s.get("introspection_enabled") or []):
        return None
    return {"name": "GraphQL endpoint present, introspection disabled",
            "severity": "POSITIVE",
            "evidence": "Endpoint(s): " + ", ".join(found[:5]) + " — introspection blocked"}
FINDING_RULES = [_r_intro, _r_found]
INTEL_FIELDS = [("GraphQL endpoints","graphql_endpoints"),
                ("Introspection enabled","introspection_enabled"),
                ("Endpoints found","endpoint_count")]
@router.post("/api/recon/graphql_intro_check")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="graphql_intro_check",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["graphql_endpoints","introspection_enabled","endpoint_count"])
def register(app):
    app.include_router(router)
