"""ransomware_leak_sites — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request, json

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    hits = []
    try:
        def _q():
            with urllib.request.urlopen("https://api.ransomware.live/recentvictims", timeout=10) as r: return json.loads(r.read())
        data = await asyncio.to_thread(_q)
        domain_root = h.split(".")[-2] if "." in h else h
        for v in (data if isinstance(data, list) else []):
            victim = (v.get("victim") or v.get("post_title") or "").lower()
            if domain_root.lower() in victim:
                hits.append({"group":v.get("group"),"victim":victim[:100],"discovered":v.get("discovered")})
    except Exception as e: ctx.state["error"] = str(e)[:120]
    ctx.state["matches"] = hits[:10]
    ctx.state["match_count"] = len(hits)
    ctx.source("ransomware.live API — recent victims matching domain root")

RULES = [
    lambda s: {"name":"Organization listed on ransomware leak site","severity":"CRITICAL",
        "evidence":f"Matches: {s.get('matches')}",
        "remediation":"Verify the listing — if real, initiate incident response immediately. Engage IR firm.",
        "cwe":"N/A","owasp":"N/A"
    } if s.get("match_count",0) > 0 else None,
]

@router.post("/api/recon/ransomware_leak_sites")
async def recon_ransomware_leak_sites(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ransomware_leak_sites",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Match Count","match_count"),("Matches","matches")])

def register(app):
    app.include_router(router)
