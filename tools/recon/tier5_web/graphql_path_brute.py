"""GraphQL Path Brute — Route: /api/recon/graphql_path_brute
Probes graphql_paths.txt. A path counts ONLY if a POST returns GraphQL-shaped
JSON (data/errors) — SPA HTML fallbacks are rejected, killing /query-style FPs."""
import asyncio
from pathlib import Path
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()
_PAYLOAD = Path(__file__).resolve().parent.parent.parent / "_payloads" / "recon" / "graphql_paths.txt"
_TO, _CONC = 5, 15
_INTROSPECT = {"query": "{__schema{queryType{name}}}"}

def _load():
    try:
        if _PAYLOAD.exists():
            return [l.strip() for l in _PAYLOAD.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")]
    except Exception: pass
    return ["/graphql","/api/graphql","/v1/graphql","/graphiql","/altair","/playground","/query"]

def _post(url, data):
    try:
        return requests.post(url, json=data, timeout=_TO, verify=False,
                             headers={"User-Agent":"VulnusLab/1.0","Content-Type":"application/json"},
                             allow_redirects=False)
    except Exception: return None

def _get(url):
    try:
        return requests.get(url, timeout=_TO, verify=False, allow_redirects=False,
                            headers={"User-Agent":"VulnusLab/1.0"})
    except Exception: return None

def _probe(base, path):
    p = path if path.startswith("/") else "/" + path
    pr = _post(base + p, _INTROSPECT)
    if not pr or pr.status_code in (404, 0): return None
    try:
        j = pr.json()
    except Exception:
        return None  # HTML / SPA fallback => not GraphQL
    if not isinstance(j, dict) or not ("data" in j or "errors" in j):
        return None  # JSON but not GraphQL-shaped
    introspect_open = bool(isinstance(j.get("data"), dict) and j["data"].get("__schema"))
    schema_data = str(j["data"])[:100] if introspect_open else None
    return {"path": p, "status": pr.status_code, "introspect": introspect_open, "schema": schema_data}

async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    r = await asyncio.to_thread(_get, base + "/")
    if not r:
        ctx.state["target_reachable"] = False; return
    ctx.state["target_reachable"] = True
    ctx.source("homepage")
    paths = _load()
    ctx.state["probed"] = len(paths)
    sem = asyncio.Semaphore(_CONC)
    async def one(p):
        async with sem: return await asyncio.to_thread(_probe, base, p)
    results = await asyncio.gather(*[one(p) for p in paths])
    hits = [h for h in results if h]
    ctx.state["endpoints"] = hits
    ctx.state["endpoints_count"] = len(hits)
    ctx.state["introspect_open"] = [h for h in hits if h["introspect"]]
    if hits: ctx.source(f"graphql ({len(hits)})")

def r_introspect(s):
    o = s.get("introspect_open") or []
    if not o: return None
    return {"name": f"GraphQL introspection enabled on production ({len(o)})",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-200", "cwe_name": "Information Exposure",
            "owasp": "A05:2021 — Security Misconfiguration",
            "evidence": "; ".join(f"{h['path']}: {h['schema']}" for h in o[:3]),
            "remediation": "Disable GraphQL introspection in production (Apollo: introspection:false; Hasura: HASURA_GRAPHQL_DEV_MODE=false)."}

def r_endpoint(s):
    e = s.get("endpoints") or []
    if not e or (s.get("introspect_open") or []): return None
    return {"name": f"GraphQL endpoint(s) discovered ({len(e)})", "severity": "INFO",
            "evidence": ", ".join(f"{h['path']} ({h['status']})" for h in e[:5])}

def r_clean(s):
    if not s.get("target_reachable"): return None
    if s.get("endpoints"): return None
    return {"name":"No GraphQL endpoints found","severity":"POSITIVE",
            "evidence":f"Probed {s.get('probed',0)} paths — none returned GraphQL-shaped JSON."}

def r_unreach(s):
    if s.get("target_reachable"): return None
    return {"name":"Target unreachable","severity":"INFO","evidence":"HTTP fetch failed"}

FINDING_RULES = [r_introspect, r_endpoint, r_clean, r_unreach]
INTEL_FIELDS = [("Target reachable","target_reachable"),("Paths probed","probed"),
                ("Endpoints found","endpoints_count")]

@router.post("/api/recon/graphql_path_brute")
async def recon_graphql_path_brute(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="graphql_path_brute",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["endpoints","introspect_open"])

def register(app): app.include_router(router)
