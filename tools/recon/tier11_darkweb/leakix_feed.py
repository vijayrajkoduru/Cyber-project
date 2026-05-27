"""leakix_feed — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request, json

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    leaks = []
    try:
        key = os.environ.get("LEAKIX_API_KEY","")
        hdr = {"Accept":"application/json"}
        if key: hdr["api-key"] = key
        def _q():
            req = urllib.request.Request(f"https://leakix.net/host/{h}", headers=hdr)
            with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read())
        d = await asyncio.to_thread(_q)
        leaks = d.get("Leaks",[]) or d.get("leaks",[]) or []
    except Exception as e: ctx.state["error"] = str(e)[:120]
    ctx.state["leaks"] = leaks[:10]
    ctx.state["leak_count"] = len(leaks)
    ctx.source("LeakIX public/keyed host endpoint")

RULES = [
    lambda s: {"name":"LeakIX flagged exposed asset for host","severity":"HIGH",
        "evidence":f"Leak entries: {s.get('leaks')[:5]}",
        "remediation":"Investigate each entry on leakix.net. Close exposed services, rotate credentials.",
        "cwe":"CWE-200","owasp":"A05:2021"
    } if s.get("leak_count",0) > 0 else None,
]

@router.post("/api/recon/leakix_feed")
async def recon_leakix_feed(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="leakix_feed",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Leak Count","leak_count"),("Leaks","leaks")])

def register(app):
    app.include_router(router)
