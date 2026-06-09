"""API version skew / shadow endpoints. VL-FORGE Vuln tier5 §5 #78/#69."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import run_scanner
from tools.vuln._vuln_common import http_get, detect_spa_catchall, is_same_as_canary
router = APIRouter()
_PATHS = ["/api/v1/","/api/v2/","/api/v3/","/v1/","/v2/","/api/"]
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    # SPA-detect: React/Vue/Angular catch-all returns 200 for /v1/, /v2/ etc.
    # with identical HTML shell. Without SPA suppression every SPA target
    # false-positives as "multiple API versions reachable".
    # (User feedback 2026-06-09)
    spa = await detect_spa_catchall(base)
    ctx.state["spa_detected"] = spa["is_spa"]
    live = []
    spa_suppressed = []
    for p in _PATHS:
        r = await asyncio.to_thread(http_get, base + p)
        if not r or not r.get("status") or int(r["status"]) in (0, 404):
            continue
        body = r.get("body", "") or ""
        # SPA suppression: if path returns the same shell as the canary,
        # it's not a real API endpoint - just SPA catch-all routing.
        if spa["is_spa"] and is_same_as_canary(body, spa["canary_body"]):
            spa_suppressed.append(f"{p} (SPA shell)")
            continue
        # Confidence: a real API endpoint returns JSON, OpenAPI, or another
        # API-shaped payload. HTML responses are almost certainly the SPA.
        ctype = (r.get("headers") or {}).get("content-type", "").lower()
        looks_api = "json" in ctype or "xml" in ctype or body.lstrip().startswith(("{", "["))
        if not looks_api:
            spa_suppressed.append(f"{p} (non-API content-type)")
            continue
        live.append(f"{p} ({r['status']})")
    ctx.source("http"); ctx.state["probed"] = 1; ctx.state["live_api_paths"] = live
    if spa_suppressed:
        ctx.state["spa_suppressed_findings"] = spa_suppressed
    vers = set()
    for p in live:
        for v in ("v1","v2","v3"):
            if "/" + v + "/" in p: vers.add(v)
    ctx.state["versions"] = sorted(vers)
def _r(s):
    v = s.get("versions") or []
    if len(v) < 2: return None
    return {"name": f"Multiple API versions reachable ({', '.join(v)}) - possible shadow/zombie API", "severity": "LOW", "cvss": 4.3, "cwe": "CWE-1059",
            "evidence": f"Reachable: {', '.join(s.get('live_api_paths') or [])}. Older versions often miss current authz/validation fixes.",
            "remediation": "Decommission or gate deprecated API versions; maintain an API inventory (OWASP API9)."}
def _r_clean(s):
    if not s.get("probed") or len(s.get("versions") or []) >= 2: return None
    return {"name": "No conflicting API versions exposed", "severity": "POSITIVE", "evidence": f"Reachable API paths: {', '.join(s.get('live_api_paths') or []) or 'none'}; no version skew."}
FINDING_RULES = [_r, _r_clean]; INTEL_FIELDS = [("Reachable API paths","live_api_paths")]
@router.post("/api/vuln/api_versioning_skew")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="api_versioning_skew", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
