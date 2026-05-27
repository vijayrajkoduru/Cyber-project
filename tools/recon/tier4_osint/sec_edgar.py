"""sec_edgar — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    name = h.split(".")[0]
    code, d = await get_json(f"https://efts.sec.gov/LATEST/search-index?q=%22{urllib.parse.quote(name)}%22&forms=10-K",
                             headers={"User-Agent":"VulnusLab admin@vulnuslab.com"})
    hits = d.get("hits",{}).get("hits",[]) if isinstance(d,dict) else []
    ctx.state["sec_filings"] = [{"cik":h2.get("_source",{}).get("ciks",[""])[0],"form":h2.get("_source",{}).get("form")} for h2 in hits[:10]]
    ctx.state["filing_count"] = len(hits)
    ctx.source("SEC EDGAR full-text search")

RULES = [

]

@router.post("/api/recon/sec_edgar")
async def recon_sec_edgar(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="sec_edgar",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Sec Filings","sec_filings"),("Filing Count","filing_count")])

def register(app):
    app.include_router(router)
