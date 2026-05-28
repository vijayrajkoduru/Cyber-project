"""API Endpoint Brute — Route: /api/recon/api_endpoint_brute
Probes common API paths. Confirms via non-404 + JSON/auth. Suppresses SPA
catch-all false positives (Netlify/Vercel return 200+index.html for every path)."""
import asyncio, random, string
from pathlib import Path
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner

router = APIRouter()
_PAYLOAD = Path(__file__).resolve().parent.parent.parent / "_payloads" / "recon" / "api_endpoints.txt"
_MAX, _TO, _CONC = 200, 4, 30

def _load():
    try:
        if _PAYLOAD.exists():
            return [l.strip() for l in _PAYLOAD.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")][:_MAX]
    except Exception: pass
    return ["/api/","/api/v1/","/api/v2/","/v1/","/v2/","/api/users","/api/admin",
            "/api/docs","/swagger.json","/openapi.json","/graphql"]

def _get(url):
    try:
        return requests.get(url, timeout=_TO, verify=False, allow_redirects=False,
                            headers={"User-Agent":"VulnusLab/1.0"})
    except Exception: return None

def _probe(base, path):
    p = path if path.startswith("/") else "/" + path
    r = _get(base + p)
    if not r: return None
    if r.status_code in (404, 0): return None
    ct = r.headers.get("Content-Type","").lower()
    is_json = "json" in ct or "javascript" in ct
    is_auth = r.status_code in (401, 403)
    return {"path": p, "status": r.status_code, "ct": ct[:40],
            "is_json": is_json, "is_auth": is_auth, "size": len(r.content or b"")}

async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    r = await asyncio.to_thread(_get, base + "/")
    if not r:
        ctx.state["target_reachable"] = False; return
    ctx.state["target_reachable"] = True
    ctx.source("homepage")
    # SPA catch-all baseline — a path that cannot legitimately exist
    _nonsense = "/" + "".join(random.choices(string.ascii_lowercase, k=24)) + "-vlnope"
    _bl = await asyncio.to_thread(_probe, base, _nonsense)
    paths = _load()
    ctx.state["probed"] = len(paths)
    sem = asyncio.Semaphore(_CONC)
    async def one(p):
        async with sem: return await asyncio.to_thread(_probe, base, p)
    results = await asyncio.gather(*[one(p) for p in paths])
    hits = [h for h in results if h]
    # If the nonsense path "exists" and is not JSON, the site soft-200s every
    # path (SPA fallback). Drop hits matching that status+size; keep real
    # JSON/auth endpoints (genuine API surface differs from index.html).
    spa = bool(_bl and not _bl["is_json"])
    if spa:
        _bs, _bsz = _bl["status"], _bl["size"]
        hits = [h for h in hits if h["is_json"] or h["is_auth"]
                or not (h["status"] == _bs and abs(h["size"] - _bsz) <= 64)]
    ctx.state["spa_catchall"] = spa
    ctx.state["hits"] = hits
    ctx.state["hits_count"] = len(hits)
    ctx.state["json_endpoints"] = [h for h in hits if h["is_json"] and not h["is_auth"]]
    ctx.state["auth_endpoints"] = [h for h in hits if h["is_auth"]]
    if hits: ctx.source(f"endpoints ({len(hits)})")

def r_open_json(s):
    j = s.get("json_endpoints") or []
    if not j: return None
    return {"name": f"Unauthenticated JSON API endpoints exposed ({len(j)})",
            "severity": "HIGH", "cwe": "CWE-285", "cwe_name": "Improper Authorization",
            "owasp": "A01:2021 — Broken Access Control",
            "evidence": ", ".join(f"{h['path']} ({h['status']}, {h['size']}B)" for h in j[:5]),
            "remediation": "Require authentication on all API endpoints. Audit each for sensitive data exposure."}

def r_auth(s):
    a = s.get("auth_endpoints") or []
    if not a: return None
    return {"name": f"Authenticated API endpoints discovered ({len(a)})",
            "severity": "MEDIUM", "cwe": "CWE-200",
            "evidence": ", ".join(f"{h['path']} ({h['status']})" for h in a[:5]),
            "remediation": "Endpoints returning 401/403 confirm API surface. Test for IDOR / auth bypass on these paths."}

def r_clean(s):
    if not s.get("target_reachable"): return None
    if s.get("hits"): return None
    base = f"Probed {s.get('probed',0)} paths"
    return {"name": "No common API endpoints found", "severity": "POSITIVE",
            "evidence": (base + " — SPA catch-all suppressed.") if s.get("spa_catchall") else (base + " — all returned 404.")}

def r_unreach(s):
    if s.get("target_reachable"): return None
    return {"name": "Target unreachable","severity":"INFO","evidence":"HTTP fetch failed"}

FINDING_RULES = [r_open_json, r_auth, r_clean, r_unreach]
INTEL_FIELDS = [("Target reachable","target_reachable"),("Paths probed","probed"),
                ("Endpoints found","hits_count")]

@router.post("/api/recon/api_endpoint_brute")
async def recon_api_endpoint_brute(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="api_endpoint_brute",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["hits","json_endpoints","auth_endpoints"])

def register(app): app.include_router(router)
