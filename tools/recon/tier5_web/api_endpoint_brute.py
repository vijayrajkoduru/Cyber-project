"""API Endpoint Brute — Route: /api/recon/api_endpoint_brute
Probes common API paths. Confirms via non-404 + JSON/auth. Suppresses SPA
catch-all false positives (Netlify/Vercel return 200+index.html for every path)."""
import asyncio, random, string
from pathlib import Path
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import set_auth_from_req, current_auth

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
    # AUTHED-RECON-V1 — pull session from contextvar set by endpoint, so
    # authenticated probes reach protected /api/users etc. instead of 401.
    hdrs = {"User-Agent": "VulnusLab/1.0"}
    a = current_auth()
    if a["auth_cookie"]:
        hdrs["Cookie"] = a["auth_cookie"]
    if a["auth_bearer"]:
        hdrs["Authorization"] = f"Bearer {a['auth_bearer']}"
    try:
        return requests.get(url, timeout=_TO, verify=False, allow_redirects=False,
                            headers=hdrs)
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

def _r_chain_handoff(s):
    hits = (s.get("hits") or [])
    if not hits: return None
    chain_next = []
    matched = []
    for h in hits:
        p = (h.get("path") or "").lower()
        if any(k in p for k in ("login","oauth","token","auth","signin","session")):
            for n in ("jwt_forge_audit","oauth_token_audit","patator_http_form_brute"):
                if n not in chain_next: chain_next.append(n)
            matched.append((p,"auth"))
        if "admin" in p:
            for n in ("exposed_env_scan","patator_http_form_brute"):
                if n not in chain_next: chain_next.append(n)
            matched.append((p,"admin"))
        if "graphql" in p:
            for n in ("graphql_intro_check","graphql_path_brute"):
                if n not in chain_next: chain_next.append(n)
            matched.append((p,"graphql"))
        if any(k in p for k in ("swagger","openapi","/docs","api-docs")):
            if "swagger_openapi_discovery" not in chain_next:
                chain_next.append("swagger_openapi_discovery")
            matched.append((p,"swagger"))
        if any(k in p for k in ("/user","/users","/data","/account","/profile","/order")):
            if "session_predict_audit" not in chain_next:
                chain_next.append("session_predict_audit")
            matched.append((p,"rest"))
        if any(v in p for v in ("/api/v1","/api/v2","/api/v3","/v1/","/v2/","/v3/")):
            if "api_versioning_skew" not in chain_next:
                chain_next.append("api_versioning_skew")
            matched.append((p,"versioned"))
        if any(k in p for k in ("/ws","/websocket","/socket")):
            for n in ("websocket_security","websocket_origin_audit"):
                if n not in chain_next: chain_next.append(n)
            matched.append((p,"ws"))
        if any(k in p for k in ("apikey=","api_key=","access_token=","key=")):
            if "api_key_in_url_leak" not in chain_next:
                chain_next.append("api_key_in_url_leak")
            matched.append((p,"keyleak"))
    if not chain_next: return None
    evidence_parts = [f"{p}->{kind}" for p,kind in matched[:8]]
    return {
        "name": "Cross-module chain handoff - API endpoints map to follow-up auth + injection scanners",
        "severity": "INFO",
        "evidence": f"Discovered {len(hits)} endpoint(s); patterns suggest {len(chain_next)} follow-up scanner(s): " + ", ".join(evidence_parts),
        "remediation": "Each endpoint type opens auth + injection surface. Run JWT/OAuth/session audits + parameter discovery.",
        "cwe": "CWE-1006",
        "chain_next": chain_next,
        "discovery_method": "api_endpoints_to_auth_chain",
        "source_stage": "chain_handoff",
        "confidence": "INFO",
    }

FINDING_RULES = [r_open_json, r_auth, _r_chain_handoff, r_clean, r_unreach]
INTEL_FIELDS = [("Target reachable","target_reachable"),("Paths probed","probed"),
                ("Endpoints found","hits_count")]

@router.post("/api/recon/api_endpoint_brute")
async def recon_api_endpoint_brute(req: ScanRequest, _=Depends(verify_scan_quota)):
    set_auth_from_req(req)
    return await run_scanner(host=recon_host(req.target), tool="api_endpoint_brute",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["hits","json_endpoints","auth_endpoints"])

def register(app): app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "api_endpoint_brute", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}

from tools._methodology import chain_registry
chain_registry.register("api_endpoint_brute", _chain_callable)
