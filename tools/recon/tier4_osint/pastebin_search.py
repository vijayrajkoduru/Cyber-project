"""pastebin_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    # psbdmp.ws is public pastebin search
    code, d = await get_json(f"https://psbdmp.ws/api/search/{urllib.parse.quote(h)}")
    hits = (d or {{}}).get("data",[]) if isinstance(d,dict) else []
    ctx.state["pastebin_hits"] = hits[:10]
    ctx.state["hit_count"] = len(hits)
    ctx.source("psbdmp.ws Pastebin dump search")

RULES = [
    lambda s: {"name":"Domain referenced in public pastebin dumps","severity":"MEDIUM",
        "evidence":f"{s.get('hit_count')} paste hits — could contain leaked creds, internal data",
        "remediation":"Review each paste; rotate any leaked credentials; subscribe to leak monitoring",
        "cwe":"CWE-359","owasp":"A07:2021"
    } if s.get("hit_count",0) > 0 else None,
]

@router.post("/api/recon/pastebin_search")
async def recon_pastebin_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="pastebin_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Pastebin Hits","pastebin_hits"),("Hit Count","hit_count")])

def register(app):
    app.include_router(router)
