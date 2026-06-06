"""Webhook Endpoint Brute — Route: /api/recon/webhook_endpoint_brute
Probes webhook_patterns.txt for exposed webhook receivers."""
import asyncio
from pathlib import Path
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import set_auth_from_req, current_auth

router = APIRouter()
_PAYLOAD = Path(__file__).resolve().parent.parent.parent / "_payloads" / "recon" / "webhook_patterns.txt"
_MAX, _TO, _CONC = 150, 4, 25

def _load():
    try:
        if _PAYLOAD.exists():
            return [l.strip() for l in _PAYLOAD.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")][:_MAX]
    except Exception: pass
    return ["/webhook","/webhooks","/api/webhook","/hooks","/api/hooks","/callback","/notify"]

def _req(url, method="GET"):
    hdrs = {"User-Agent": "VulnusLab/1.0"}
    a = current_auth()
    if a["auth_cookie"]: hdrs["Cookie"] = a["auth_cookie"]
    if a["auth_bearer"]: hdrs["Authorization"] = f"Bearer {a['auth_bearer']}"
    try:
        return requests.request(method, url, timeout=_TO, verify=False, allow_redirects=False,
                                headers=hdrs)
    except Exception: return None

def _probe(base, path):
    p = path if path.startswith("/") else "/" + path
    rg = _req(base + p, "GET")
    rp = _req(base + p, "POST")
    if not rg and not rp: return None
    g_status = rg.status_code if rg else None
    p_status = rp.status_code if rp else None
    if g_status == 404 and p_status in (404, None): return None
    if g_status is None and p_status == 404: return None
    accepts_post = p_status and p_status not in (404, 405, 501)
    return {"path": p, "get": g_status, "post": p_status, "accepts_post": accepts_post}

async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    r = _req(base + "/", "GET")
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
    ctx.state["hits"] = hits
    ctx.state["hits_count"] = len(hits)
    ctx.state["post_accepting"] = [h for h in hits if h["accepts_post"]]
    if hits: ctx.source(f"webhooks ({len(hits)})")

def r_post(s):
    p = s.get("post_accepting") or []
    if not p: return None
    return {"name": f"Webhook endpoints accept POST without auth ({len(p)})",
            "severity": "MEDIUM", "cvss": 5.5, "cwe": "CWE-352",
            "cwe_name": "Cross-Site Request Forgery",
            "owasp": "A01:2021 — Broken Access Control",
            "evidence": ", ".join(f"{h['path']} (POST→{h['post']})" for h in p[:5]),
            "remediation": "Require HMAC signature on all webhook receivers. Validate origin. Don't process POST bodies on unauth endpoints."}

def r_disco(s):
    h = s.get("hits") or []
    if not h: return None
    if s.get("post_accepting"): return None
    return {"name": f"Webhook endpoints exist but reject POST ({len(h)})",
            "severity": "INFO",
            "evidence": ", ".join(f"{x['path']} (GET={x['get']})" for x in h[:5])}

def r_clean(s):
    if not s.get("target_reachable"): return None
    if s.get("hits"): return None
    return {"name":"No webhook endpoints found","severity":"POSITIVE",
            "evidence":f"Probed {s.get('probed',0)} patterns — all 404."}

def r_unreach(s):
    if s.get("target_reachable"): return None
    return {"name":"Target unreachable","severity":"INFO","evidence":"HTTP fetch failed"}

FINDING_RULES = [r_post, r_disco, r_clean, r_unreach]
INTEL_FIELDS = [("Target reachable","target_reachable"),("Patterns probed","probed"),
                ("Webhooks found","hits_count")]

@router.post("/api/recon/webhook_endpoint_brute")
async def recon_webhook_endpoint_brute(req: ScanRequest, _=Depends(verify_scan_quota)):
    set_auth_from_req(req)
    return await run_scanner(host=recon_host(req.target), tool="webhook_endpoint_brute",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["hits","post_accepting"])

def register(app): app.include_router(router)
