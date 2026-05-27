"""threatfox_check — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import json, urllib.request

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    try:
        def _post():
            req = urllib.request.Request("https://threatfox-api.abuse.ch/api/v1/",
                data=json.dumps({"query":"search_ioc","search_term":h}).encode(),
                headers={"Content-Type":"application/json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                return json.loads(r.read())
        d = await asyncio.to_thread(_post)
        hits = d.get("data",[]) if d.get("query_status")=="ok" else []
    except Exception as e:
        hits = []; ctx.state["error"] = str(e)[:120]
    ctx.state["ioc_hits"] = hits[:10]
    ctx.state["hit_count"] = len(hits)
    ctx.source("ThreatFox public IOC database (abuse.ch)")

RULES = [
    lambda s: {"name":"Target listed in ThreatFox IOC database","severity":"HIGH",
        "evidence":f"IOC entries: {s.get('ioc_hits')}",
        "remediation":"If your IP/domain is listed: investigate origin (compromise/misuse), then submit removal request to abuse.ch",
        "cwe":"N/A","owasp":"N/A"
    } if s.get("hit_count",0) > 0 else None,
]

@router.post("/api/recon/threatfox_check")
async def recon_threatfox_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="threatfox_check",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Ioc Hits","ioc_hits"),("Hit Count","hit_count")])

def register(app):
    app.include_router(router)
