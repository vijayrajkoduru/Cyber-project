"""GraphQL Introspection Check — VL-FORGE. No endpoint / 404 => clean (no finding)."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import set_auth_from_req, current_auth
router = APIRouter()
PATHS = ["/graphql","/api/graphql","/v1/graphql","/graphql/v1","/query","/gql","/graphiql","/playground"]
INTRO = {"query": "{__schema{queryType{name}}}"}
DEEP_INTRO = {"query": "{__schema{queryType{name fields{name}} mutationType{name fields{name}} subscriptionType{name fields{name}} types{name}}}"}

def _authed_headers():
    h = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    a = current_auth()
    if a["auth_cookie"]:
        h["Cookie"] = a["auth_cookie"]
    if a["auth_bearer"]:
        h["Authorization"] = f"Bearer {a['auth_bearer']}"
    return h

def _probe(url):
    try:
        r = requests.post(url, json=INTRO, timeout=8, headers=_authed_headers())
    except Exception:
        return None
    if r.status_code >= 400:
        return None
    try:
        j = r.json()
    except Exception:
        return None
    if isinstance(j, dict) and isinstance(j.get("data"), dict) and j["data"].get("__schema"):
        deep = _deep_probe(url)
        return {"url": url, "introspection": True, "schema": deep}
    if isinstance(j, dict) and ("data" in j or "errors" in j):
        return {"url": url, "introspection": False, "schema": None}
    return None
def _deep_probe(url):
    try:
        r = requests.post(url, json=DEEP_INTRO, timeout=10, headers=_authed_headers())
        j = r.json()
        sch = (j.get("data") or {}).get("__schema") or {}
    except Exception:
        return None
    qf = [(f or {}).get("name","") for f in ((sch.get("queryType") or {}).get("fields") or [])]
    mf = [(f or {}).get("name","") for f in ((sch.get("mutationType") or {}).get("fields") or [])]
    sf = [(f or {}).get("name","") for f in ((sch.get("subscriptionType") or {}).get("fields") or [])]
    tn = [(t or {}).get("name","") for t in (sch.get("types") or [])]
    return {"queries": qf, "mutations": mf, "subscriptions": sf, "types": tn}
async def gather(ctx):
    h = str(ctx.host)
    base = h if h.startswith("http") else "https://" + h
    urls = [base.rstrip("/") + p for p in PATHS]
    res = await asyncio.gather(*[asyncio.to_thread(_probe, u) for u in urls])
    hits = [x for x in res if x]
    ctx.source("probed-%d-paths" % len(urls))
    # Aggregate schema signals across all endpoints
    all_mutations, all_queries, all_subs, all_types = [], [], [], []
    for x in hits:
        sch = x.get("schema") or {}
        all_queries += sch.get("queries") or []
        all_mutations += sch.get("mutations") or []
        all_subs += sch.get("subscriptions") or []
        all_types += sch.get("types") or []
    auth_kw = ("login","signin","signup","register","refreshtoken","refresh_token","authenticate","authtoken")
    admin_kw = ("admin","users","allusers","listusers","deleteuser","internal","secret","config")
    fed_kw = ("_service","_entities","sdl")
    has_auth = any(any(k in (m or "").lower() for k in auth_kw) for m in all_mutations)
    has_admin = any(any(k in (q or "").lower() for k in admin_kw) for q in all_queries)
    has_subs = len(all_subs) > 0
    has_fed = any(any(k in (n or "").lower() for k in fed_kw) for n in (all_queries + all_types))
    ctx.state.update({
        "graphql_endpoints": [x["url"] for x in hits],
        "introspection_enabled": [x["url"] for x in hits if x["introspection"]],
        "endpoint_count": len(hits),
        "auth_mutations_present": has_auth,
        "admin_queries_present": has_admin,
        "subscriptions_present": has_subs,
        "federation_present": has_fed,
        "mutation_names": all_mutations[:20],
        "query_names": all_queries[:20],
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
    set_auth_from_req(req)
    return await run_scanner(host=recon_host(req.target), tool="graphql_intro_check",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["graphql_endpoints","introspection_enabled","endpoint_count"])
def register(app):
    app.include_router(router)
