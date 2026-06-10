"""OAuth/OIDC PKCE (S256) advertisement audit via discovery doc. VL-FORGE Vuln tier12 §12 #180.

VL-VERIFY: http_json already returns None if the response is HTML (SPA
shell isn't valid JSON), so this scanner is inherently SPA-safe. We stamp
spa_catchall onto state for report transparency only.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import run_scanner
from tools.vuln._vuln_common import http_json, detect_spa_catchall
router = APIRouter()
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/"); cfg = None; src = None
    spa = await detect_spa_catchall(base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    for path in ("/.well-known/openid-configuration","/.well-known/oauth-authorization-server"):
        d = await asyncio.to_thread(http_json, base + path)
        if isinstance(d, dict) and (d.get("authorization_endpoint") or d.get("token_endpoint")):
            cfg = d; src = path; break
    if not cfg:
        ctx.state["skipped_reason"] = "no OIDC/OAuth discovery document at /.well-known/* (not an OAuth provider)"; return
    ctx.source("oidc"); ctx.state["probed"] = 1; ctx.state["disco"] = src
    methods = cfg.get("code_challenge_methods_supported")
    ctx.state["pkce_methods"] = methods if methods else "none advertised"
    ctx.state["pkce_ok"] = bool(methods) and ("S256" in methods)
def _r(s):
    if not s.get("disco") or s.get("pkce_ok"): return None
    return {"name": "OAuth/OIDC server does not advertise PKCE (S256)", "severity": "MEDIUM", "cvss": 5.4, "cwe": "CWE-1390",
            "evidence": f"Discovery {s.get('disco')} -> code_challenge_methods_supported: {s.get('pkce_methods')}. PKCE S256 is mandatory (RFC 9700 / OAuth 2.1).",
            "remediation": "Enable and require PKCE with S256 for all authorization-code flows; advertise it in discovery metadata."}
def _r_clean(s):
    if not s.get("disco") or not s.get("pkce_ok"): return None
    return {"name": "OAuth/OIDC server advertises PKCE (S256)", "severity": "POSITIVE", "evidence": f"code_challenge_methods_supported includes S256 ({s.get('disco')})."}
FINDING_RULES = [_r, _r_clean]; INTEL_FIELDS = [("Discovery doc","disco"),("PKCE methods","pkce_methods")]
@router.post("/api/vuln/oauth_pkce_missing")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="oauth_pkce_missing", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
